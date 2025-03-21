// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025, Kylin Software */

#include "mptcp_bpf.h"
#include "mptcp_bpf_pm.h"

char _license[] SEC("license") = "GPL";

extern bool CONFIG_MPTCP_IPV6 __kconfig __weak;

extern unsigned int
mptcp_pm_get_add_addr_signal_max(const struct mptcp_sock *msk) __ksym;
extern unsigned int
mptcp_pm_get_add_addr_accept_max(const struct mptcp_sock *msk) __ksym;
extern unsigned int
mptcp_pm_get_subflows_max(const struct mptcp_sock *msk) __ksym;
extern unsigned int
mptcp_pm_get_local_addr_max(const struct mptcp_sock *msk) __ksym;
extern void bpf_bitmap_fill(unsigned long *dst__ign, unsigned int nbits) __ksym;

extern bool mptcp_pm_is_init_remote_addr(struct mptcp_sock *msk,
					 const struct mptcp_addr_info *remote) __ksym;
extern bool mptcp_pm_add_addr_recv(struct mptcp_sock *msk) __ksym;
extern void mptcp_pm_create_subflow_or_signal_addr(struct mptcp_sock *msk) __ksym;
extern void mptcp_pm_rm_addr_recv(struct mptcp_sock *msk) __ksym;
extern int mptcp_pm_nl_append_new_local_addr_msk(struct mptcp_sock *msk,
						 struct mptcp_pm_addr_entry *entry,
						 bool needs_id, bool replace) __ksym;
extern struct mptcp_pm_addr_entry *
mptcp_pm_nl_lookup_addr(struct mptcp_sock *msk,
			const struct mptcp_addr_info *info) __ksym;

extern struct mptcp_pm_addr_entry *
bpf_kmemdup_entry(struct mptcp_pm_addr_entry *entry,
		  int size, gfp_t priority) __ksym;
extern void
bpf_kfree_entry(struct mptcp_pm_addr_entry *entry) __ksym;

static void mptcp_pm_copy_addr(struct mptcp_addr_info *dst,
			       const struct mptcp_addr_info *src)
{
	dst->id = src->id;
	dst->family = src->family;
	dst->port = src->port;

	if (src->family == AF_INET) {
		dst->addr.s_addr = src->addr.s_addr;
	} else if (src->family == AF_INET6) {
		dst->addr6.s6_addr32[0] = src->addr6.s6_addr32[0];
		dst->addr6.s6_addr32[1] = src->addr6.s6_addr32[1];
		dst->addr6.s6_addr32[2] = src->addr6.s6_addr32[2];
		dst->addr6.s6_addr32[3] = src->addr6.s6_addr32[3];
	}
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_netlink_get_local_id, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *skc)
{
	struct mptcp_pm_addr_entry *entry;
	int ret;

	bpf_rcu_read_lock();
	entry = mptcp_pm_nl_lookup_addr(msk, &skc->addr);
	ret = entry ? entry->addr.id : -1;
	bpf_rcu_read_unlock();
	if (ret >= 0)
		return ret;

	entry = bpf_kmemdup_entry(skc, sizeof(*skc), GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;

	entry->addr.port = 0;
	ret = mptcp_pm_nl_append_new_local_addr_msk(msk, entry, true, false);
	if (ret < 0)
		bpf_kfree_entry(entry);

	return 0;
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_netlink_get_priority, struct mptcp_sock *msk,
	      struct mptcp_addr_info *skc)
{
	struct mptcp_pm_addr_entry *entry;
	bool backup;

	bpf_rcu_read_lock();
	entry = mptcp_pm_nl_lookup_addr(msk, skc);
	backup = entry && !!(entry->flags & MPTCP_PM_ADDR_FLAG_BACKUP);
	bpf_rcu_read_unlock();

	return backup;
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_netlink_established, struct mptcp_sock *msk)
{
	bpf_spin_lock_bh(&msk->pm.lock);
	mptcp_pm_create_subflow_or_signal_addr(msk);
	bpf_spin_unlock_bh(&msk->pm.lock);
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_netlink_subflow_established, struct mptcp_sock *msk)
{
	bpf_spin_lock_bh(&msk->pm.lock);
	mptcp_pm_create_subflow_or_signal_addr(msk);
	bpf_spin_unlock_bh(&msk->pm.lock);
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_netlink_allow_new_subflow, struct mptcp_sock *msk)
{
	struct mptcp_pm_data *pm = &msk->pm;
	unsigned int subflows_max;
	int ret = 0;

	subflows_max = mptcp_pm_get_subflows_max(msk);

	/* try to avoid acquiring the lock below */
	if (!READ_ONCE(pm->accept_subflow))
		return false;

	bpf_spin_lock_bh(&pm->lock);
	if (READ_ONCE(pm->accept_subflow)) {
		ret = pm->subflows < subflows_max;
		if (ret && ++pm->subflows == subflows_max)
			WRITE_ONCE(pm->accept_subflow, false);
	}
	bpf_spin_unlock_bh(&pm->lock);

	return ret;
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_netlink_accept_new_subflow, const struct mptcp_sock *msk)
{
	return READ_ONCE(msk->pm.accept_subflow);
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_netlink_add_addr_echo, struct mptcp_sock *msk,
	      const struct mptcp_addr_info *addr)
{
	return (addr->id == 0 && !mptcp_pm_is_init_remote_addr(msk, addr)) ||
	       (addr->id > 0 && !READ_ONCE(msk->pm.accept_addr));
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_netlink_add_addr_received, struct mptcp_sock *msk,
	     const struct mptcp_addr_info *addr)
{
	int ret = 0;

	if (mptcp_pm_add_addr_recv(msk))
		mptcp_pm_copy_addr(&msk->pm.remote, addr);
	else
		ret = -EINVAL;
	return ret;
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_netlink_rm_addr_received, struct mptcp_sock *msk)
{
	mptcp_pm_rm_addr_recv(msk);
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_netlink_init, struct mptcp_sock *msk)
{
	bool subflows_allowed = !!mptcp_pm_get_subflows_max(msk);
	struct mptcp_pm_data *pm = &msk->pm;

	bpf_printk("BPF netlink PM (%s)",
		   CONFIG_MPTCP_IPV6 ? "IPv6" : "IPv4");

	WRITE_ONCE(pm->work_pending,
		   (!!mptcp_pm_get_local_addr_max(msk) &&
		    subflows_allowed) ||
		   !!mptcp_pm_get_add_addr_signal_max(msk));
	WRITE_ONCE(pm->accept_addr,
		   !!mptcp_pm_get_add_addr_accept_max(msk) &&
		   subflows_allowed);
	WRITE_ONCE(pm->accept_subflow, subflows_allowed);

	bpf_bitmap_fill(pm->id_avail_bitmap, MPTCP_PM_MAX_ADDR_ID + 1);
}

SEC(".struct_ops.link")
struct mptcp_pm_ops bpf_netlink = {
	.get_local_id		= (void *)mptcp_pm_netlink_get_local_id,
	.get_priority		= (void *)mptcp_pm_netlink_get_priority,
	.established		= (void *)mptcp_pm_netlink_established,
	.subflow_established	= (void *)mptcp_pm_netlink_subflow_established,
	.allow_new_subflow	= (void *)mptcp_pm_netlink_allow_new_subflow,
	.accept_new_subflow	= (void *)mptcp_pm_netlink_accept_new_subflow,
	.add_addr_echo		= (void *)mptcp_pm_netlink_add_addr_echo,
	.add_addr_received	= (void *)mptcp_pm_netlink_add_addr_received,
	.rm_addr_received	= (void *)mptcp_pm_netlink_rm_addr_received,
	.init			= (void *)mptcp_pm_netlink_init,
	.name			= "bpf_netlink",
};
