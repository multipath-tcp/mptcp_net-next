// SPDX-License-Identifier: GPL-2.0
/*
 * Functions related to generic helpers functions
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/scatterlist.h>

#include "blk.h"

struct bio *blk_next_bio(struct bio *bio, unsigned int nr_pages, gfp_t gfp)
{
	struct bio *new = bio_alloc(gfp, nr_pages);

	if (bio) {
		bio_chain(bio, new);
		submit_bio(bio);
	}

	return new;
}
EXPORT_SYMBOL_GPL(blk_next_bio);

int __blkdev_issue_discard(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, int flags,
		struct bio **biop)
{
	struct request_queue *q = bdev_get_queue(bdev);
	struct bio *bio = *biop;
	unsigned int op;
	sector_t bs_mask, part_offset = 0;

	if (!q)
		return -ENXIO;

	if (bdev_read_only(bdev))
		return -EPERM;

	if (flags & BLKDEV_DISCARD_SECURE) {
		if (!blk_queue_secure_erase(q))
			return -EOPNOTSUPP;
		op = REQ_OP_SECURE_ERASE;
	} else {
		if (!blk_queue_discard(q))
			return -EOPNOTSUPP;
		op = REQ_OP_DISCARD;
	}

	/* In case the discard granularity isn't set by buggy device driver */
	if (WARN_ON_ONCE(!q->limits.discard_granularity)) {
		char dev_name[BDEVNAME_SIZE];

		bdevname(bdev, dev_name);
		pr_err_ratelimited("%s: Error: discard_granularity is 0.\n", dev_name);
		return -EOPNOTSUPP;
	}

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

	if (!nr_sects)
		return -EINVAL;

	/* In case the discard request is in a partition */
	if (bdev_is_partition(bdev))
		part_offset = bdev->bd_start_sect;

	while (nr_sects) {
		sector_t granularity_aligned_lba, req_sects;
		sector_t sector_mapped = sector + part_offset;

		granularity_aligned_lba = round_up(sector_mapped,
				q->limits.discard_granularity >> SECTOR_SHIFT);

		/*
		 * Check whether the discard bio starts at a discard_granularity
		 * aligned LBA,
		 * - If no: set (granularity_aligned_lba - sector_mapped) to
		 *   bi_size of the first split bio, then the second bio will
		 *   start at a discard_granularity aligned LBA on the device.
		 * - If yes: use bio_aligned_discard_max_sectors() as the max
		 *   possible bi_size of the first split bio. Then when this bio
		 *   is split in device drive, the split ones are very probably
		 *   to be aligned to discard_granularity of the device's queue.
		 */
		if (granularity_aligned_lba == sector_mapped)
			req_sects = min_t(sector_t, nr_sects,
					  bio_aligned_discard_max_sectors(q));
		else
			req_sects = min_t(sector_t, nr_sects,
					  granularity_aligned_lba - sector_mapped);

		WARN_ON_ONCE((req_sects << 9) > UINT_MAX);

		bio = blk_next_bio(bio, 0, gfp_mask);
		bio->bi_iter.bi_sector = sector;
		bio_set_dev(bio, bdev);
		bio_set_op_attrs(bio, op, 0);

		bio->bi_iter.bi_size = req_sects << 9;
		sector += req_sects;
		nr_sects -= req_sects;

		/*
		 * We can loop for a long time in here, if someone does
		 * full device discards (like mkfs). Be nice and allow
		 * us to schedule out to avoid softlocking if preempt
		 * is disabled.
		 */
		cond_resched();
	}

	*biop = bio;
	return 0;
}
EXPORT_SYMBOL(__blkdev_issue_discard);

/**
 * blkdev_issue_discard - queue a discard
 * @bdev:	blockdev to issue discard for
 * @sector:	start sector
 * @nr_sects:	number of sectors to discard
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @flags:	BLKDEV_DISCARD_* flags to control behaviour
 *
 * Description:
 *    Issue a discard request for the sectors in question.
 */
int blkdev_issue_discard(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, unsigned long flags)
{
	struct bio *bio = NULL;
	struct blk_plug plug;
	int ret;

	blk_start_plug(&plug);
	ret = __blkdev_issue_discard(bdev, sector, nr_sects, gfp_mask, flags,
			&bio);
	if (!ret && bio) {
		ret = submit_bio_wait(bio);
		if (ret == -EOPNOTSUPP)
			ret = 0;
		bio_put(bio);
	}
	blk_finish_plug(&plug);

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_discard);

/*
 * Wait on and process all in-flight BIOs.  This must only be called once
 * all bios have been issued so that the refcount can only decrease.
 * This just waits for all bios to make it through bio_copy_end_io. IO
 * errors are propagated through cio->io_error.
 */
static int cio_await_completion(struct cio *cio)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&cio->lock, flags);
	if (cio->refcount) {
		cio->waiter = current;
		__set_current_state(TASK_UNINTERRUPTIBLE);
		spin_unlock_irqrestore(&cio->lock, flags);
		blk_io_schedule();
		/* wake up sets us TASK_RUNNING */
		spin_lock_irqsave(&cio->lock, flags);
		cio->waiter = NULL;
		ret = cio->io_err;
	}
	spin_unlock_irqrestore(&cio->lock, flags);
	kvfree(cio);

	return ret;
}

static void bio_copy_end_io(struct bio *bio)
{
	struct copy_ctx *ctx = bio->bi_private;
	struct cio *cio = ctx->cio;
	sector_t clen;
	int ri = ctx->range_idx;
	unsigned long flags;

	if (bio->bi_status) {
		cio->io_err = bio->bi_status;
		clen = (bio->bi_iter.bi_sector - ctx->start_sec) << SECTOR_SHIFT;
		cio->rlist[ri].comp_len = min_t(sector_t, clen, cio->rlist[ri].comp_len);
	}
	__free_page(bio->bi_io_vec[0].bv_page);
	kfree(ctx);
	bio_put(bio);

	spin_lock_irqsave(&cio->lock, flags);
	if (!--cio->refcount && cio->waiter)
		wake_up_process(cio->waiter);
	spin_unlock_irqrestore(&cio->lock, flags);
}

/*
 * blk_copy_offload	- Use device's native copy offload feature
 * Go through user provide payload, prepare new payload based on device's copy offload limits.
 */
int blk_copy_offload(struct block_device *src_bdev, int nr_srcs,
		struct range_entry *rlist, struct block_device *dst_bdev, gfp_t gfp_mask)
{
	struct request_queue *sq = bdev_get_queue(src_bdev);
	struct request_queue *dq = bdev_get_queue(dst_bdev);
	struct bio *read_bio, *write_bio;
	struct copy_ctx *ctx;
	struct cio *cio;
	struct page *token;
	sector_t src_blk, copy_len, dst_blk;
	sector_t remaining, max_copy_len = LONG_MAX;
	unsigned long flags;
	int ri = 0, ret = 0;

	cio = kzalloc(sizeof(struct cio), GFP_KERNEL);
	if (!cio)
		return -ENOMEM;
	cio->rlist = rlist;
	spin_lock_init(&cio->lock);

	max_copy_len = min_t(sector_t, sq->limits.max_copy_sectors, dq->limits.max_copy_sectors);
	max_copy_len = min3(max_copy_len, (sector_t)sq->limits.max_copy_range_sectors,
			(sector_t)dq->limits.max_copy_range_sectors) << SECTOR_SHIFT;

	for (ri = 0; ri < nr_srcs; ri++) {
		cio->rlist[ri].comp_len = rlist[ri].len;
		src_blk = rlist[ri].src;
		dst_blk = rlist[ri].dst;
		for (remaining = rlist[ri].len; remaining > 0; remaining -= copy_len) {
			copy_len = min(remaining, max_copy_len);

			token = alloc_page(gfp_mask);
			if (unlikely(!token)) {
				ret = -ENOMEM;
				goto err_token;
			}

			ctx = kzalloc(sizeof(struct copy_ctx), gfp_mask);
			if (!ctx) {
				ret = -ENOMEM;
				goto err_ctx;
			}
			ctx->cio = cio;
			ctx->range_idx = ri;
			ctx->start_sec = rlist[ri].src;

			read_bio = bio_alloc(src_bdev, 1, REQ_OP_READ | REQ_COPY | REQ_NOMERGE,
					gfp_mask);
			if (!read_bio) {
				ret = -ENOMEM;
				goto err_read_bio;
			}
			read_bio->bi_iter.bi_sector = src_blk >> SECTOR_SHIFT;
			read_bio->bi_iter.bi_size = copy_len;
			__bio_add_page(read_bio, token, PAGE_SIZE, 0);
			ret = submit_bio_wait(read_bio);
			bio_put(read_bio);
			if (ret)
				goto err_read_bio;

			write_bio = bio_alloc(dst_bdev, 1, REQ_OP_WRITE | REQ_COPY | REQ_NOMERGE,
					gfp_mask);
			if (!write_bio) {
				ret = -ENOMEM;
				goto err_read_bio;
			}
			write_bio->bi_iter.bi_sector = dst_blk >> SECTOR_SHIFT;
			write_bio->bi_iter.bi_size = copy_len;
			__bio_add_page(write_bio, token, PAGE_SIZE, 0);
			write_bio->bi_end_io = bio_copy_end_io;
			write_bio->bi_private = ctx;

			spin_lock_irqsave(&cio->lock, flags);
			++cio->refcount;
			spin_unlock_irqrestore(&cio->lock, flags);

			submit_bio(write_bio);
			src_blk += copy_len;
			dst_blk += copy_len;
		}
	}

	/* Wait for completion of all IO's*/
	return cio_await_completion(cio);

err_read_bio:
	kfree(ctx);
err_ctx:
	__free_page(token);
err_token:
	rlist[ri].comp_len = min_t(sector_t, rlist[ri].comp_len, (rlist[ri].len - remaining));

	cio->io_err = ret;
	return cio_await_completion(cio);
}

int blk_submit_rw_buf(struct block_device *bdev, void *buf, sector_t buf_len,
				sector_t sector, unsigned int op, gfp_t gfp_mask)
{
	struct request_queue *q = bdev_get_queue(bdev);
	struct bio *bio, *parent = NULL;
	sector_t max_hw_len = min_t(unsigned int, queue_max_hw_sectors(q),
			queue_max_segments(q) << (PAGE_SHIFT - SECTOR_SHIFT)) << SECTOR_SHIFT;
	sector_t len, remaining;
	int ret;

	for (remaining = buf_len; remaining > 0; remaining -= len) {
		len = min_t(int, max_hw_len, remaining);
retry:
		bio = bio_map_kern(q, buf, len, gfp_mask);
		if (IS_ERR(bio)) {
			len >>= 1;
			if (len)
				goto retry;
			return PTR_ERR(bio);
		}

		bio->bi_iter.bi_sector = sector >> SECTOR_SHIFT;
		bio->bi_opf = op;
		bio_set_dev(bio, bdev);
		bio->bi_end_io = NULL;
		bio->bi_private = NULL;

		if (parent) {
			bio_chain(parent, bio);
			submit_bio(parent);
		}
		parent = bio;
		sector += len;
		buf = (char *) buf + len;
	}
	ret = submit_bio_wait(bio);
	bio_put(bio);

	return ret;
}

static void *blk_alloc_buf(sector_t req_size, sector_t *alloc_size, gfp_t gfp_mask)
{
	int min_size = PAGE_SIZE;
	void *buf;

	while (req_size >= min_size) {
		buf = kvmalloc(req_size, gfp_mask);
		if (buf) {
			*alloc_size = req_size;
			return buf;
		}
		/* retry half the requested size */
		req_size >>= 1;
	}

	return NULL;
}

static inline int blk_copy_sanity_check(struct block_device *src_bdev,
		struct block_device *dst_bdev, struct range_entry *rlist, int nr)
{
	unsigned int align_mask = max(
			bdev_logical_block_size(dst_bdev), bdev_logical_block_size(src_bdev)) - 1;
	sector_t len = 0;
	int i;

	for (i = 0; i < nr; i++) {
		if (rlist[i].len)
			len += rlist[i].len;
		else
			return -EINVAL;
		if ((rlist[i].dst & align_mask) || (rlist[i].src & align_mask) ||
				(rlist[i].len & align_mask))
			return -EINVAL;
		rlist[i].comp_len = 0;
	}

	if (len && len >= MAX_COPY_TOTAL_LENGTH)
		return -EINVAL;

	return 0;
}

static inline sector_t blk_copy_max_range(struct range_entry *rlist, int nr, sector_t *max_len)
{
	int i;
	sector_t len = 0;

	*max_len = 0;
	for (i = 0; i < nr; i++) {
		*max_len = max(*max_len, rlist[i].len);
		len += rlist[i].len;
	}

	return len;
}

/*
 * If native copy offload feature is absent, this function tries to emulate,
 * by copying data from source to a temporary buffer and from buffer to
 * destination device.
 */
static int blk_copy_emulate(struct block_device *src_bdev, int nr,
		struct range_entry *rlist, struct block_device *dest_bdev, gfp_t gfp_mask)
{
	void *buf = NULL;
	int ret, nr_i = 0;
	sector_t src, dst, copy_len, buf_len, read_len, copied_len, max_len = 0, remaining = 0;

	copy_len = blk_copy_max_range(rlist, nr, &max_len);
	buf = blk_alloc_buf(max_len, &buf_len, gfp_mask);
	if (!buf)
		return -ENOMEM;

	for (copied_len = 0; copied_len < copy_len; copied_len += read_len) {
		if (!remaining) {
			rlist[nr_i].comp_len = 0;
			src = rlist[nr_i].src;
			dst = rlist[nr_i].dst;
			remaining = rlist[nr_i++].len;
		}

		read_len = min_t(sector_t, remaining, buf_len);
		ret = blk_submit_rw_buf(src_bdev, buf, read_len, src, REQ_OP_READ, gfp_mask);
		if (ret)
			goto out;
		src += read_len;
		remaining -= read_len;
		ret = blk_submit_rw_buf(dest_bdev, buf, read_len, dst, REQ_OP_WRITE,
				gfp_mask);
		if (ret)
			goto out;
		else
			rlist[nr_i - 1].comp_len += read_len;
		dst += read_len;
	}
out:
	kvfree(buf);
	return ret;
}

static inline bool blk_check_copy_offload(struct request_queue *src_q,
		struct request_queue *dest_q)
{
	if (blk_queue_copy(dest_q) && blk_queue_copy(src_q))
		return true;

	return false;
}

/*
 * blkdev_issue_copy - queue a copy
 * @src_bdev:	source block device
 * @nr_srcs:	number of source ranges to copy
 * @rlist:	array of source/dest/len
 * @dest_bdev:	destination block device
 * @gfp_mask:   memory allocation flags (for bio_alloc)
 *
 * Description:
 *	Copy source ranges from source block device to destination block device.
 *	length of a source range cannot be zero.
 */
int blkdev_issue_copy(struct block_device *src_bdev, int nr,
		struct range_entry *rlist, struct block_device *dest_bdev, gfp_t gfp_mask)
{
	struct request_queue *src_q = bdev_get_queue(src_bdev);
	struct request_queue *dest_q = bdev_get_queue(dest_bdev);
	int ret = -EINVAL;

	if (!src_q || !dest_q)
		return -ENXIO;

	if (!nr)
		return -EINVAL;

	if (nr >= MAX_COPY_NR_RANGE)
		return -EINVAL;

	if (bdev_read_only(dest_bdev))
		return -EPERM;

	ret = blk_copy_sanity_check(src_bdev, dest_bdev, rlist, nr);
	if (ret)
		return ret;

	if (blk_check_copy_offload(src_q, dest_q))
		ret = blk_copy_offload(src_bdev, nr, rlist, dest_bdev, gfp_mask);
	else
		ret = blk_copy_emulate(src_bdev, nr, rlist, dest_bdev, gfp_mask);

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_copy);

/**
 * __blkdev_issue_write_same - generate number of bios with same page
 * @bdev:	target blockdev
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @page:	page containing data to write
 * @biop:	pointer to anchor bio
 *
 * Description:
 *  Generate and issue number of bios(REQ_OP_WRITE_SAME) with same page.
 */
static int __blkdev_issue_write_same(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, struct page *page,
		struct bio **biop)
{
	struct request_queue *q = bdev_get_queue(bdev);
	unsigned int max_write_same_sectors;
	struct bio *bio = *biop;
	sector_t bs_mask;

	if (!q)
		return -ENXIO;

	if (bdev_read_only(bdev))
		return -EPERM;

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

	if (!bdev_write_same(bdev))
		return -EOPNOTSUPP;

	/* Ensure that max_write_same_sectors doesn't overflow bi_size */
	max_write_same_sectors = bio_allowed_max_sectors(q);

	while (nr_sects) {
		bio = blk_next_bio(bio, 1, gfp_mask);
		bio->bi_iter.bi_sector = sector;
		bio_set_dev(bio, bdev);
		bio->bi_vcnt = 1;
		bio->bi_io_vec->bv_page = page;
		bio->bi_io_vec->bv_offset = 0;
		bio->bi_io_vec->bv_len = bdev_logical_block_size(bdev);
		bio_set_op_attrs(bio, REQ_OP_WRITE_SAME, 0);

		if (nr_sects > max_write_same_sectors) {
			bio->bi_iter.bi_size = max_write_same_sectors << 9;
			nr_sects -= max_write_same_sectors;
			sector += max_write_same_sectors;
		} else {
			bio->bi_iter.bi_size = nr_sects << 9;
			nr_sects = 0;
		}
		cond_resched();
	}

	*biop = bio;
	return 0;
}

/**
 * blkdev_issue_write_same - queue a write same operation
 * @bdev:	target blockdev
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @page:	page containing data
 *
 * Description:
 *    Issue a write same request for the sectors in question.
 */
int blkdev_issue_write_same(struct block_device *bdev, sector_t sector,
				sector_t nr_sects, gfp_t gfp_mask,
				struct page *page)
{
	struct bio *bio = NULL;
	struct blk_plug plug;
	int ret;

	blk_start_plug(&plug);
	ret = __blkdev_issue_write_same(bdev, sector, nr_sects, gfp_mask, page,
			&bio);
	if (ret == 0 && bio) {
		ret = submit_bio_wait(bio);
		bio_put(bio);
	}
	blk_finish_plug(&plug);
	return ret;
}
EXPORT_SYMBOL(blkdev_issue_write_same);

static int __blkdev_issue_write_zeroes(struct block_device *bdev,
		sector_t sector, sector_t nr_sects, gfp_t gfp_mask,
		struct bio **biop, unsigned flags)
{
	struct bio *bio = *biop;
	unsigned int max_write_zeroes_sectors;
	struct request_queue *q = bdev_get_queue(bdev);

	if (!q)
		return -ENXIO;

	if (bdev_read_only(bdev))
		return -EPERM;

	/* Ensure that max_write_zeroes_sectors doesn't overflow bi_size */
	max_write_zeroes_sectors = bdev_write_zeroes_sectors(bdev);

	if (max_write_zeroes_sectors == 0)
		return -EOPNOTSUPP;

	while (nr_sects) {
		bio = blk_next_bio(bio, 0, gfp_mask);
		bio->bi_iter.bi_sector = sector;
		bio_set_dev(bio, bdev);
		bio->bi_opf = REQ_OP_WRITE_ZEROES;
		if (flags & BLKDEV_ZERO_NOUNMAP)
			bio->bi_opf |= REQ_NOUNMAP;

		if (nr_sects > max_write_zeroes_sectors) {
			bio->bi_iter.bi_size = max_write_zeroes_sectors << 9;
			nr_sects -= max_write_zeroes_sectors;
			sector += max_write_zeroes_sectors;
		} else {
			bio->bi_iter.bi_size = nr_sects << 9;
			nr_sects = 0;
		}
		cond_resched();
	}

	*biop = bio;
	return 0;
}

/*
 * Convert a number of 512B sectors to a number of pages.
 * The result is limited to a number of pages that can fit into a BIO.
 * Also make sure that the result is always at least 1 (page) for the cases
 * where nr_sects is lower than the number of sectors in a page.
 */
static unsigned int __blkdev_sectors_to_bio_pages(sector_t nr_sects)
{
	sector_t pages = DIV_ROUND_UP_SECTOR_T(nr_sects, PAGE_SIZE / 512);

	return min(pages, (sector_t)BIO_MAX_VECS);
}

static int __blkdev_issue_zero_pages(struct block_device *bdev,
		sector_t sector, sector_t nr_sects, gfp_t gfp_mask,
		struct bio **biop)
{
	struct request_queue *q = bdev_get_queue(bdev);
	struct bio *bio = *biop;
	int bi_size = 0;
	unsigned int sz;

	if (!q)
		return -ENXIO;

	if (bdev_read_only(bdev))
		return -EPERM;

	while (nr_sects != 0) {
		bio = blk_next_bio(bio, __blkdev_sectors_to_bio_pages(nr_sects),
				   gfp_mask);
		bio->bi_iter.bi_sector = sector;
		bio_set_dev(bio, bdev);
		bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

		while (nr_sects != 0) {
			sz = min((sector_t) PAGE_SIZE, nr_sects << 9);
			bi_size = bio_add_page(bio, ZERO_PAGE(0), sz, 0);
			nr_sects -= bi_size >> 9;
			sector += bi_size >> 9;
			if (bi_size < sz)
				break;
		}
		cond_resched();
	}

	*biop = bio;
	return 0;
}

/**
 * __blkdev_issue_zeroout - generate number of zero filed write bios
 * @bdev:	blockdev to issue
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @biop:	pointer to anchor bio
 * @flags:	controls detailed behavior
 *
 * Description:
 *  Zero-fill a block range, either using hardware offload or by explicitly
 *  writing zeroes to the device.
 *
 *  If a device is using logical block provisioning, the underlying space will
 *  not be released if %flags contains BLKDEV_ZERO_NOUNMAP.
 *
 *  If %flags contains BLKDEV_ZERO_NOFALLBACK, the function will return
 *  -EOPNOTSUPP if no explicit hardware offload for zeroing is provided.
 */
int __blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, struct bio **biop,
		unsigned flags)
{
	int ret;
	sector_t bs_mask;

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

	ret = __blkdev_issue_write_zeroes(bdev, sector, nr_sects, gfp_mask,
			biop, flags);
	if (ret != -EOPNOTSUPP || (flags & BLKDEV_ZERO_NOFALLBACK))
		return ret;

	return __blkdev_issue_zero_pages(bdev, sector, nr_sects, gfp_mask,
					 biop);
}
EXPORT_SYMBOL(__blkdev_issue_zeroout);

/**
 * blkdev_issue_zeroout - zero-fill a block range
 * @bdev:	blockdev to write
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @flags:	controls detailed behavior
 *
 * Description:
 *  Zero-fill a block range, either using hardware offload or by explicitly
 *  writing zeroes to the device.  See __blkdev_issue_zeroout() for the
 *  valid values for %flags.
 */
int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, unsigned flags)
{
	int ret = 0;
	sector_t bs_mask;
	struct bio *bio;
	struct blk_plug plug;
	bool try_write_zeroes = !!bdev_write_zeroes_sectors(bdev);

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

retry:
	bio = NULL;
	blk_start_plug(&plug);
	if (try_write_zeroes) {
		ret = __blkdev_issue_write_zeroes(bdev, sector, nr_sects,
						  gfp_mask, &bio, flags);
	} else if (!(flags & BLKDEV_ZERO_NOFALLBACK)) {
		ret = __blkdev_issue_zero_pages(bdev, sector, nr_sects,
						gfp_mask, &bio);
	} else {
		/* No zeroing offload support */
		ret = -EOPNOTSUPP;
	}
	if (ret == 0 && bio) {
		ret = submit_bio_wait(bio);
		bio_put(bio);
	}
	blk_finish_plug(&plug);
	if (ret && try_write_zeroes) {
		if (!(flags & BLKDEV_ZERO_NOFALLBACK)) {
			try_write_zeroes = false;
			goto retry;
		}
		if (!bdev_write_zeroes_sectors(bdev)) {
			/*
			 * Zeroing offload support was indicated, but the
			 * device reported ILLEGAL REQUEST (for some devices
			 * there is no non-destructive way to verify whether
			 * WRITE ZEROES is actually supported).
			 */
			ret = -EOPNOTSUPP;
		}
	}

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_zeroout);
