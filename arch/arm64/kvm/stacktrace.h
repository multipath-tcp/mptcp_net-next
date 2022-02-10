/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Stack unwinder for EL2 nVHE hypervisor.
 */

#ifndef __KVM_HYP_STACKTRACE_H
#define __KVM_HYP_STACKTRACE_H

#ifdef CONFIG_NVHE_EL2_DEBUG
void hyp_dump_backtrace(unsigned long hyp_offset);
#else
static inline void hyp_dump_backtrace(unsigned long hyp_offset)
{
}
#endif /* CONFIG_NVHE_EL2_DEBUG */

#endif /* __KVM_HYP_STACKTRACE_H */
