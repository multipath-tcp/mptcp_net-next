// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025, Kylin Software */

#include "mptcp_bpf.h"

char _license[] SEC("license") = "GPL";

extern bool CONFIG_MPTCP_IPV6 __kconfig __weak;

extern void bpf_list_add_tail_rcu(struct list_head *new,
				  struct list_head *head) __ksym;
extern void bpf_list_del_rcu(struct list_head *entry) __ksym;

SEC("struct_ops")
void BPF_PROG(mptcp_userspace_pm_init, struct mptcp_sock *msk)
{
	bpf_printk("BPF userspace PM (%s)",
		   CONFIG_MPTCP_IPV6 ? "IPv6" : "IPv4");
}

SEC("struct_ops")
void BPF_PROG(mptcp_userspace_pm_release, struct mptcp_sock *msk)
{
}

static struct mptcp_pm_addr_entry *
mptcp_userspace_pm_lookup_addr(struct mptcp_sock *msk,
			       const struct mptcp_addr_info *addr)
{
	struct mptcp_pm_addr_entry *entry;

	bpf_for_each(mptcp_userspace_pm_addr, entry, (struct sock *)msk) {
		if (mptcp_addresses_equal(&entry->addr, addr, false))
			return entry;
	}
	return NULL;
}

static int mptcp_userspace_pm_append_new_local_addr(struct mptcp_sock *msk,
						    struct mptcp_pm_addr_entry *entry,
						    bool needs_id)
{
	struct sock *sk = (struct sock *)msk;
	unsigned long id_bitmap[4] = { 0 };
	struct mptcp_pm_addr_entry *e;
	bool addr_match = false;
	bool id_match = false;
	int ret = -EINVAL;

	bpf_bitmap_zero(id_bitmap, MPTCP_PM_MAX_ADDR_ID + 1);

	bpf_spin_lock_bh(&msk->pm.lock);
	bpf_for_each(mptcp_userspace_pm_addr, e, sk) {
		addr_match = mptcp_addresses_equal(&e->addr, &entry->addr, true);
		if (addr_match && entry->addr.id == 0 && needs_id)
			entry->addr.id = e->addr.id;
		id_match = (e->addr.id == entry->addr.id);
		if (addr_match || id_match)
			break;
		bpf_set_bit(e->addr.id, id_bitmap);
	}

	if (!addr_match && !id_match) {
		/* Memory for the entry is allocated from the
		 * sock option buffer.
		 */
		e = bpf_sock_kmalloc_entry(sk, sizeof(*e), GFP_ATOMIC);
		if (!e) {
			ret = -ENOMEM;
			goto append_err;
		}

		mptcp_pm_copy_entry(e, entry);
		if (!e->addr.id && needs_id)
			e->addr.id = bpf_find_next_zero_bit(id_bitmap,
							    MPTCP_PM_MAX_ADDR_ID + 1,
							    1);
		bpf_list_add_tail_rcu(&e->list, &msk->pm.userspace_pm_local_addr_list);
		msk->pm.local_addr_used++;
		ret = e->addr.id;
	} else if (addr_match && id_match) {
		ret = entry->addr.id;
	}

append_err:
	bpf_spin_unlock_bh(&msk->pm.lock);
	return ret;
}

SEC("struct_ops")
int BPF_PROG(mptcp_userspace_pm_address_announced, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local)
{
	int err;

	err = mptcp_userspace_pm_append_new_local_addr(msk, local, false);
	if (err < 0)
		return err;

	bpf_spin_lock_bh(&msk->pm.lock);

	if (mptcp_pm_alloc_anno_list(msk, &local->addr)) {
		msk->pm.add_addr_signaled++;
		mptcp_pm_announce_addr(msk, &local->addr, false);
		mptcp_pm_nl_addr_send_ack(msk);
	}

	bpf_spin_unlock_bh(&msk->pm.lock);

	return 0;
}

static struct mptcp_pm_addr_entry *
mptcp_userspace_pm_lookup_addr_by_id(struct mptcp_sock *msk, unsigned int id)
{
	struct mptcp_pm_addr_entry *entry;

	bpf_for_each(mptcp_userspace_pm_addr, entry, (struct sock *)msk) {
		if (entry->addr.id == id)
			return entry;
	}
	return NULL;
}

SEC("struct_ops")
int BPF_PROG(mptcp_userspace_pm_address_removed, struct mptcp_sock *msk, u8 id)
{
	struct mptcp_pm_addr_entry *entry;

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr_by_id(msk, id);
	if (!entry) {
		bpf_spin_unlock_bh(&msk->pm.lock);
		return -EINVAL;
	}

	bpf_list_del_rcu(&entry->list);
	bpf_spin_unlock_bh(&msk->pm.lock);

	mptcp_pm_remove_addr_entry(msk, entry);

	bpf_sock_kfree_entry((struct sock *)msk, entry, sizeof(*entry));

	return 0;
}

static int mptcp_userspace_pm_delete_local_addr(struct mptcp_sock *msk,
						struct mptcp_pm_addr_entry *addr)
{
	struct sock *sk = (struct sock *)msk;
	struct mptcp_pm_addr_entry *entry;

	entry = mptcp_userspace_pm_lookup_addr(msk, &addr->addr);
	if (!entry)
		return -EINVAL;

	bpf_list_del_rcu(&entry->list);
	bpf_sock_kfree_entry(sk, entry, sizeof(*entry));
	msk->pm.local_addr_used--;
	return 0;
}

SEC("struct_ops")
int BPF_PROG(mptcp_userspace_pm_subflow_established, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local, struct mptcp_addr_info *remote)
{
	struct sock *sk = (struct sock *)msk;
	int err;

	err = mptcp_userspace_pm_append_new_local_addr(msk, local, false);
	if (err < 0)
		return err;

	err = bpf_mptcp_subflow_connect(sk, local, remote);
	bpf_spin_lock_bh(&msk->pm.lock);
	if (err)
		mptcp_userspace_pm_delete_local_addr(msk, local);
	else
		msk->pm.subflows++;
	bpf_spin_unlock_bh(&msk->pm.lock);

	return err;
}

SEC("struct_ops")
int BPF_PROG(mptcp_userspace_pm_subflow_closed, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local, struct mptcp_addr_info *remote)
{
	struct sock *ssk, *sk = (struct sock *)msk;
	struct mptcp_subflow_context *subflow;

	ssk = mptcp_pm_find_ssk(msk, &local->addr, remote);
	if (!ssk)
		return -ESRCH;

	subflow = bpf_mptcp_subflow_ctx(ssk);
	if (!subflow)
		return -EINVAL;

	bpf_spin_lock_bh(&msk->pm.lock);
	mptcp_userspace_pm_delete_local_addr(msk, local);
	bpf_spin_unlock_bh(&msk->pm.lock);
	mptcp_subflow_shutdown(sk, ssk, RCV_SHUTDOWN | SEND_SHUTDOWN);
	mptcp_close_ssk(sk, ssk, subflow);
	BPF_MPTCP_INC_STATS(bpf_sock_net(sk), MPTCP_MIB_RMSUBFLOW);

	return 0;
}

SEC("struct_ops")
int BPF_PROG(mptcp_userspace_pm_get_local_id, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *skc)
{
	struct mptcp_pm_addr_entry *entry;

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr(msk, &skc->addr);
	bpf_spin_unlock_bh(&msk->pm.lock);
	if (entry)
		return entry->addr.id;

	return mptcp_userspace_pm_append_new_local_addr(msk, skc, true);
}

SEC("struct_ops")
bool BPF_PROG(mptcp_userspace_pm_get_priority, struct mptcp_sock *msk,
	      struct mptcp_addr_info *skc)
{
	struct mptcp_pm_addr_entry *entry;
	bool backup;

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr(msk, skc);
	backup = entry && !!(entry->flags & MPTCP_PM_ADDR_FLAG_BACKUP);
	bpf_spin_unlock_bh(&msk->pm.lock);

	return backup;
}

SEC("struct_ops")
int BPF_PROG(mptcp_userspace_pm_set_priority, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local, struct mptcp_addr_info *remote)
{
	struct mptcp_pm_addr_entry *entry;
	u8 bkup = 0;

	if (local->flags & MPTCP_PM_ADDR_FLAG_BACKUP)
		bkup = 1;

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr(msk, &local->addr);
	if (entry) {
		if (bkup)
			entry->flags |= MPTCP_PM_ADDR_FLAG_BACKUP;
		else
			entry->flags &= ~MPTCP_PM_ADDR_FLAG_BACKUP;
	}
	bpf_spin_unlock_bh(&msk->pm.lock);

	return mptcp_pm_nl_mp_prio_send_ack(msk, &local->addr, remote, bkup);
}

SEC(".struct_ops.link")
struct mptcp_pm_ops userspace_pm = {
	.address_announced	= (void *)mptcp_userspace_pm_address_announced,
	.address_removed	= (void *)mptcp_userspace_pm_address_removed,
	.subflow_established	= (void *)mptcp_userspace_pm_subflow_established,
	.subflow_closed		= (void *)mptcp_userspace_pm_subflow_closed,
	.get_local_id		= (void *)mptcp_userspace_pm_get_local_id,
	.get_priority		= (void *)mptcp_userspace_pm_get_priority,
	.set_priority		= (void *)mptcp_userspace_pm_set_priority,
	.init			= (void *)mptcp_userspace_pm_init,
	.release		= (void *)mptcp_userspace_pm_release,
	.type			= MPTCP_PM_TYPE_BPF_USERSPACE,
};
