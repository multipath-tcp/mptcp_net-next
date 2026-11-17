// SPDX-License-Identifier: GPL-2.0
/* Renesas R-Car Gen4 gPTP device driver
 *
 * Copyright (C) 2026 Renesas Electronics Corporation
 * Copyright (C) 2026 Niklas Söderlund <niklas.soderlund@ragnatech.se>
 */

#include <linux/clk.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/types.h>

#define PTPTMEC_REG		0x0010
#define PTPTMDC_REG		0x0014
#define PTPTIVC0_REG		0x0020
#define PTPTOVC00_REG		0x0030
#define PTPTOVC10_REG		0x0034
#define PTPTOVC20_REG		0x0038
#define PTPGPTPTM00_REG		0x0050
#define PTPGPTPTM10_REG		0x0054
#define PTPGPTPTM20_REG		0x0058

struct ptp_rcar_gen4_priv {
	void __iomem *base;
	struct clk *clk;

	struct ptp_clock *clock;
	struct ptp_clock_info info;

	spinlock_t lock;	/* Registers access. */
	s64 default_addend;
};

#define ptp_to_priv(ptp) container_of(ptp, struct ptp_rcar_gen4_priv, info)

static int ptp_rcar_gen4_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct ptp_rcar_gen4_priv *priv = ptp_to_priv(ptp);
	s64 addend = priv->default_addend;
	bool neg_adj = scaled_ppm < 0;
	unsigned long flags;
	s64 diff;

	if (neg_adj)
		scaled_ppm = -scaled_ppm;
	diff = div_s64(addend * scaled_ppm_to_ppb(scaled_ppm), NSEC_PER_SEC);
	addend = neg_adj ? addend - diff : addend + diff;

	spin_lock_irqsave(&priv->lock, flags);
	iowrite32(addend, priv->base + PTPTIVC0_REG);
	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

static void _ptp_rcar_gen4_gettime(struct ptp_clock_info *ptp,
				   struct timespec64 *ts)
{
	struct ptp_rcar_gen4_priv *priv = ptp_to_priv(ptp);

	lockdep_assert_held(&priv->lock);

	ts->tv_nsec = ioread32(priv->base + PTPGPTPTM00_REG);
	ts->tv_sec = ioread32(priv->base + PTPGPTPTM10_REG) |
		((s64)ioread32(priv->base + PTPGPTPTM20_REG) << 32);
}

static int ptp_rcar_gen4_gettime(struct ptp_clock_info *ptp,
				 struct timespec64 *ts)
{
	struct ptp_rcar_gen4_priv *priv = ptp_to_priv(ptp);
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	_ptp_rcar_gen4_gettime(ptp, ts);
	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

static void _ptp_rcar_gen4_settime(struct ptp_clock_info *ptp,
				   const struct timespec64 *ts)
{
	struct ptp_rcar_gen4_priv *priv = ptp_to_priv(ptp);

	lockdep_assert_held(&priv->lock);

	iowrite32(1, priv->base + PTPTMDC_REG);
	iowrite32(0, priv->base + PTPTOVC20_REG);
	iowrite32(0, priv->base + PTPTOVC10_REG);
	iowrite32(0, priv->base + PTPTOVC00_REG);
	iowrite32(1, priv->base + PTPTMEC_REG);
	iowrite32(ts->tv_sec >> 32, priv->base + PTPTOVC20_REG);
	iowrite32(ts->tv_sec, priv->base + PTPTOVC10_REG);
	iowrite32(ts->tv_nsec, priv->base + PTPTOVC00_REG);
}

static int ptp_rcar_gen4_settime(struct ptp_clock_info *ptp,
				 const struct timespec64 *ts)
{
	struct ptp_rcar_gen4_priv *priv = ptp_to_priv(ptp);
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	_ptp_rcar_gen4_settime(ptp, ts);
	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

static int ptp_rcar_gen4_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct ptp_rcar_gen4_priv *priv = ptp_to_priv(ptp);
	struct timespec64 ts;
	unsigned long flags;
	s64 now;

	spin_lock_irqsave(&priv->lock, flags);
	_ptp_rcar_gen4_gettime(ptp, &ts);
	now = ktime_to_ns(timespec64_to_ktime(ts));
	ts = ns_to_timespec64(now + delta);
	_ptp_rcar_gen4_settime(ptp, &ts);
	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

static struct ptp_clock_info ptp_rcar_gen4_info = {
	.owner = THIS_MODULE,
	.name = "R-Car Gen4 gPTP",
	.max_adj = 50000000,
	.adjfine = ptp_rcar_gen4_adjfine,
	.adjtime = ptp_rcar_gen4_adjtime,
	.gettime64 = ptp_rcar_gen4_gettime,
	.settime64 = ptp_rcar_gen4_settime,
};

static int ptp_rcar_gen4_probe(struct platform_device *pdev)
{
	struct ptp_rcar_gen4_priv *priv;
	struct device *dev = &pdev->dev;
	unsigned long rate;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	platform_set_drvdata(pdev, priv);

	priv->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->base))
		return PTR_ERR(priv->base);

	priv->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(priv->clk))
		return PTR_ERR(priv->clk);

	rate = clk_get_rate(priv->clk);
	if (!rate)
		return -ENODEV;

	spin_lock_init(&priv->lock);

	priv->info = ptp_rcar_gen4_info;

	/* Default timer increment in ns.
	 * bit[31:27] - integer
	 * bit[26:0]  - decimal
	 * increment[ns] = perid[ns] * 2^27 => (1ns * 2^27) / rate[hz]
	 */

	priv->default_addend = div_s64(1000000000LL << 27, rate);

	pm_runtime_enable(dev);
	pm_runtime_resume_and_get(dev);

	iowrite32(priv->default_addend, priv->base + PTPTIVC0_REG);
	iowrite32(1, priv->base + PTPTMEC_REG);

	priv->clock = ptp_clock_register(&priv->info, dev);
	if (IS_ERR(priv->clock)) {
		pm_runtime_put_sync(dev);
		pm_runtime_disable(dev);
		return PTR_ERR(priv->clock);
	}

	return 0;
}

static void ptp_rcar_gen4_remove(struct platform_device *pdev)
{
	struct ptp_rcar_gen4_priv *priv = platform_get_drvdata(pdev);
	struct device *dev = &pdev->dev;

	ptp_clock_unregister(priv->clock);

	iowrite32(1, priv->base + PTPTMDC_REG);

	pm_runtime_put_sync(dev);
	pm_runtime_disable(dev);
}

static const struct of_device_id ptp_rcar_gen4_of_match[] = {
	{ .compatible = "renesas,rcar-gen4-gptp", },
	{ /* Sentinel */ },
};
MODULE_DEVICE_TABLE(of, ptp_rcar_gen4_of_match);

static struct platform_driver ptp_rcar_gen4_driver = {
	.driver = {
		.name = "ptp-rcar-gen4",
		.of_match_table = ptp_rcar_gen4_of_match,
	},
	.probe    = ptp_rcar_gen4_probe,
	.remove   = ptp_rcar_gen4_remove,
};
module_platform_driver(ptp_rcar_gen4_driver);

MODULE_AUTHOR("Niklas Söderlund");
MODULE_DESCRIPTION("Renesas R-Car Gen4 gPTP driver");
MODULE_LICENSE("GPL");
