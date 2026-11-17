#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Measure udmabuf-backed devmem TCP throughput with kperf."""

from lib.py import cmd, defer, ethtool, EthtoolFamily, KperfRunner
from lib.py import ksft_disruptive, ksft_exit, ksft_metric, ksft_run
from lib.py import KsftSkipEx, NetDrvEpEnv


UDMABUF_LIMIT = "/sys/module/udmabuf/parameters/size_limit_mb"
UDMABUF_SIZE_MB = 2048


def _set_udmabuf_limit(host) -> None:
    current = cmd(f"cat {UDMABUF_LIMIT}", host=host).stdout.strip()
    if int(current) >= UDMABUF_SIZE_MB:
        return

    cmd(f"echo {UDMABUF_SIZE_MB} > {UDMABUF_LIMIT}", host=host, shell=True)
    defer(cmd, f"echo {current} > {UDMABUF_LIMIT}", host=host, shell=True)


def _enable_hw_gro(cfg) -> None:
    features = ethtool(f"-k {cfg.ifname}", json=True)[0]
    hw_gro = features["rx-gro-hw"]
    if not hw_gro["active"]:
        if hw_gro["fixed"]:
            raise KsftSkipEx("Test requires rx-gro-hw support")
        ethtool(f"-K {cfg.ifname} rx-gro-hw on")
        defer(ethtool, f"-K {cfg.ifname} rx-gro-hw off")


@ksft_disruptive
def kperf(cfg) -> None:
    """Measure udmabuf-backed devmem performance with kperf."""
    runner = KperfRunner(cfg)

    for name, host in (("local", None), ("remote", cfg.remote)):
        if cmd("test -c /dev/udmabuf", host=host, fail=False).ret:
            raise KsftSkipEx(f"Test requires /dev/udmabuf on the {name} host")
        _set_udmabuf_limit(host)

    # kperf reprograms the RSS indirection table for its queues.
    defer(ethtool, f"-X {cfg.ifname} default")

    _enable_hw_gro(cfg)

    ethnl = EthtoolFamily()
    rings = ethnl.rings_get({"header": {"dev-index": cfg.ifindex}})
    restore = {
        "header": {"dev-index": cfg.ifindex},
        "tcp-data-split": rings.get("tcp-data-split", "unknown"),
    }
    config = {
        "header": {"dev-index": cfg.ifindex},
        "tcp-data-split": "enabled",
    }
    # Memory providers require a zero threshold where the driver has one.
    if "hds-thresh" in rings:
        restore["hds-thresh"] = rings["hds-thresh"]
        config["hds-thresh"] = 0
    defer(ethnl.rings_set, restore)
    ethnl.rings_set(config)

    devmem_args = [
        "--time", "15",
        "--num-connections", "4",
        "--read-size", str(64 << 20),
        "--write-size", str(64 << 20),
        "--pin-off", "4",
        "--num-rx-queues", "4",
        "--dmabuf-rx-size-mb", str(UDMABUF_SIZE_MB),
        "--dmabuf-tx-size-mb", str(UDMABUF_SIZE_MB),
        "--validate", "no",
        "--devmem-rx",
        "--devmem-tx",
        "--devmem-rx-memory", "host",
        "--devmem-tx-memory", "host",
    ]

    with runner:
        result = runner.run(client_args=devmem_args)

    ksft_metric("throughput", result.target_throughput, goal="higher")


def main() -> None:
    """Run the devmem performance test."""
    with NetDrvEpEnv(__file__, nsim_test=False) as cfg:
        ksft_run([kperf], args=(cfg,))
    ksft_exit()


if __name__ == "__main__":
    main()
