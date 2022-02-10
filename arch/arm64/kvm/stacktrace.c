// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stack unwinder for EL2 nVHE hypervisor.
 *
 * Code mostly copied from the arm64 kernel stack unwinder
 * and adapted to the nVHE hypervisor.
 *
 * See: arch/arm64/kernel/stacktrace.c
 *
 * CONFIG_NVHE_EL2_DEBUG disables the host stage-2 protection
 * allowing us to access the hypervisor stack pages and
 * consequently unwind its stack from the host in EL1.
 *
 * See: __hyp_do_panic()
 */

#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <linux/kvm_host.h>
#include "stacktrace.h"

DECLARE_PER_CPU(unsigned long, kvm_arm_hyp_stack_page);
DECLARE_KVM_NVHE_PER_CPU(unsigned long [PAGE_SIZE/sizeof(long)], hyp_overflow_stack);
DECLARE_KVM_NVHE_PER_CPU(struct kvm_nvhe_panic_info, kvm_panic_info);

enum hyp_stack_type {
	HYP_STACK_TYPE_UNKNOWN,
	HYP_STACK_TYPE_HYP,
	HYP_STACK_TYPE_OVERFLOW,
	__NR_HYP_STACK_TYPES
};

struct hyp_stack_info {
	unsigned long low;
	unsigned long high;
	enum hyp_stack_type type;
};

/*
 * A snapshot of a frame record or fp/lr register values, along with some
 * accounting information necessary for robust unwinding.
 *
 * @fp:          The fp value in the frame record (or the real fp)
 * @pc:          The pc value calculated from lr in the frame record.
 *
 * @stacks_done: Stacks which have been entirely unwound, for which it is no
 *               longer valid to unwind to.
 *
 * @prev_fp:     The fp that pointed to this frame record, or a synthetic value
 *               of 0. This is used to ensure that within a stack, each
 *               subsequent frame record is at an increasing address.
 * @prev_type:   The type of stack this frame record was on, or a synthetic
 *               value of HYP_STACK_TYPE_UNKNOWN. This is used to detect a
 *               transition from one stack to another.
 */
struct hyp_stackframe {
	unsigned long fp;
	unsigned long pc;
	DECLARE_BITMAP(stacks_done, __NR_HYP_STACK_TYPES);
	unsigned long prev_fp;
	enum hyp_stack_type prev_type;
};

static inline bool __on_hyp_stack(unsigned long hyp_sp, unsigned long size,
				unsigned long low, unsigned long high,
				enum hyp_stack_type type,
				struct hyp_stack_info *info)
{
	if (!low)
		return false;

	if (hyp_sp < low || hyp_sp + size < hyp_sp || hyp_sp + size > high)
		return false;

	if (info) {
		info->low = low;
		info->high = high;
		info->type = type;
	}
	return true;
}

static inline bool on_hyp_overflow_stack(unsigned long hyp_sp, unsigned long size,
				 struct hyp_stack_info *info)
{
	struct kvm_nvhe_panic_info *panic_info = this_cpu_ptr_nvhe_sym(kvm_panic_info);
	unsigned long low = (unsigned long)panic_info->hyp_overflow_stack_base;
	unsigned long high = low + PAGE_SIZE;

	return __on_hyp_stack(hyp_sp, size, low, high, HYP_STACK_TYPE_OVERFLOW, info);
}

static inline bool on_hyp_stack(unsigned long hyp_sp, unsigned long size,
				 struct hyp_stack_info *info)
{
	struct kvm_nvhe_panic_info *panic_info = this_cpu_ptr_nvhe_sym(kvm_panic_info);
	unsigned long low = (unsigned long)panic_info->hyp_stack_base;
	unsigned long high = low + PAGE_SIZE;

	return __on_hyp_stack(hyp_sp, size, low, high, HYP_STACK_TYPE_HYP, info);
}

static inline bool on_hyp_accessible_stack(unsigned long hyp_sp, unsigned long size,
				       struct hyp_stack_info *info)
{
	if (info)
		info->type = HYP_STACK_TYPE_UNKNOWN;

	if (on_hyp_stack(hyp_sp, size, info))
		return true;
	if (on_hyp_overflow_stack(hyp_sp, size, info))
		return true;

	return false;
}

static unsigned long __hyp_stack_kern_va(unsigned long hyp_va)
{
	struct kvm_nvhe_panic_info *panic_info = this_cpu_ptr_nvhe_sym(kvm_panic_info);
	unsigned long hyp_base, kern_base, hyp_offset;

	hyp_base = (unsigned long)panic_info->hyp_stack_base;
	hyp_offset = hyp_va - hyp_base;

	kern_base = (unsigned long)*this_cpu_ptr(&kvm_arm_hyp_stack_page);

	return kern_base + hyp_offset;
}

static unsigned long __hyp_overflow_stack_kern_va(unsigned long hyp_va)
{
	struct kvm_nvhe_panic_info *panic_info = this_cpu_ptr_nvhe_sym(kvm_panic_info);
	unsigned long hyp_base, kern_base, hyp_offset;

	hyp_base = (unsigned long)panic_info->hyp_overflow_stack_base;
	hyp_offset = hyp_va - hyp_base;

	kern_base = (unsigned long)this_cpu_ptr_nvhe_sym(hyp_overflow_stack);

	return kern_base + hyp_offset;
}

/*
 * Convert hypervisor stack VA to a kernel VA.
 *
 * The hypervisor stack is mapped in the flexible 'private' VA range, to allow
 * for guard pages below the stack. Consequently, the fixed offset address
 * translation macros won't work here.
 *
 * The kernel VA is calculated as an offset from the kernel VA of the hypervisor
 * stack base. See: __hyp_stack_kern_va(),  __hyp_overflow_stack_kern_va()
 */
static unsigned long hyp_stack_kern_va(unsigned long hyp_va,
					enum hyp_stack_type stack_type)
{
	switch (stack_type) {
	case HYP_STACK_TYPE_HYP:
		return __hyp_stack_kern_va(hyp_va);
	case HYP_STACK_TYPE_OVERFLOW:
		return __hyp_overflow_stack_kern_va(hyp_va);
	default:
		return 0UL;
	}
}

/*
 * Unwind from one frame record (A) to the next frame record (B).
 *
 * We terminate early if the location of B indicates a malformed chain of frame
 * records (e.g. a cycle), determined based on the location and fp value of A
 * and the location (but not the fp value) of B.
 */
static int notrace hyp_unwind_frame(struct hyp_stackframe *frame)
{
	unsigned long fp = frame->fp, fp_kern_va;
	struct hyp_stack_info info;

	if (fp & 0x7)
		return -EINVAL;

	if (!on_hyp_accessible_stack(fp, 16, &info))
		return -EINVAL;

	if (test_bit(info.type, frame->stacks_done))
		return -EINVAL;

	/*
	 * As stacks grow downward, any valid record on the same stack must be
	 * at a strictly higher address than the prior record.
	 *
	 * Stacks can nest in the following order:
	 *
	 * HYP -> OVERFLOW
	 *
	 * ... but the nesting itself is strict. Once we transition from one
	 * stack to another, it's never valid to unwind back to that first
	 * stack.
	 */
	if (info.type == frame->prev_type) {
		if (fp <= frame->prev_fp)
			return -EINVAL;
	} else {
		set_bit(frame->prev_type, frame->stacks_done);
	}

	/* Translate the hyp stack address to a kernel address */
	fp_kern_va = hyp_stack_kern_va(fp, info.type);
	if (!fp_kern_va)
		return -EINVAL;

	/*
	 * Record this frame record's values and location. The prev_fp and
	 * prev_type are only meaningful to the next hyp_unwind_frame()
	 * invocation.
	 */
	frame->fp = READ_ONCE_NOCHECK(*(unsigned long *)(fp_kern_va));
	/* PC = LR - 4; All aarch64 instructions are 32-bits in size */
	frame->pc = READ_ONCE_NOCHECK(*(unsigned long *)(fp_kern_va + 8)) - 4;
	frame->prev_fp = fp;
	frame->prev_type = info.type;

	return 0;
}

/*
 * AArch64 PCS assigns the frame pointer to x29.
 *
 * A simple function prologue looks like this:
 *	sub	sp, sp, #0x10
 *	stp	x29, x30, [sp]
 *	mov	x29, sp
 *
 * A simple function epilogue looks like this:
 *	mov	sp, x29
 *	ldp	x29, x30, [sp]
 *	add	sp, sp, #0x10
 */
static void hyp_start_backtrace(struct hyp_stackframe *frame, unsigned long fp)
{
	frame->fp = fp;

	/*
	 * Prime the first unwind.
	 *
	 * In hyp_unwind_frame() we'll check that the FP points to a valid
	 * stack, which can't be HYP_STACK_TYPE_UNKNOWN, and the first unwind
	 * will be treated as a transition to whichever stack that happens to
	 * be. The prev_fp value won't be used, but we set it to 0 such that
	 * it is definitely not an accessible stack address. The first frame
	 * (hyp_panic()) is skipped, so we also set PC to 0.
	 */
	bitmap_zero(frame->stacks_done, __NR_HYP_STACK_TYPES);
	frame->pc = frame->prev_fp = 0;
	frame->prev_type = HYP_STACK_TYPE_UNKNOWN;
}

static void hyp_dump_backtrace_entry(unsigned long hyp_pc, unsigned long hyp_offset)
{
	unsigned long va_mask = GENMASK_ULL(vabits_actual - 1, 0);

	hyp_pc &= va_mask;
	hyp_pc += hyp_offset;

	kvm_err(" [<%016llx>]\n", hyp_pc);
}

void hyp_dump_backtrace(unsigned long hyp_offset)
{
	struct kvm_nvhe_panic_info *panic_info = this_cpu_ptr_nvhe_sym(kvm_panic_info);
	struct hyp_stackframe frame;
	int frame_nr = 0;
	int skip = 1;		/* Skip the first frame: hyp_panic() */

	kvm_err("nVHE HYP call trace (vmlinux addresses):\n");

	hyp_start_backtrace(&frame, (unsigned long)panic_info->start_fp);

	do {
		if (skip) {
			skip--;
			continue;
		}

		hyp_dump_backtrace_entry(frame.pc, hyp_offset);

		frame_nr++;
	} while (!hyp_unwind_frame(&frame));

	kvm_err("---- end of nVHE HYP call trace ----\n");
}
