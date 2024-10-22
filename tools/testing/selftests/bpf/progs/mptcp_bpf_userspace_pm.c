// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Kylin Software */

#include "bpf_tracing_net.h"
#include "mptcp_bpf.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops")
void BPF_PROG(mptcp_pm_init, struct mptcp_sock *msk)
{
	bpf_printk("BPF userspace PM (%s)",
		   CONFIG_MPTCP_IPV6 ? "IPv6" : "IPv4");
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_release, struct mptcp_sock *msk)
{
}

static int mptcp_userspace_pm_append_new_local_addr(struct mptcp_sock *msk,
						    struct mptcp_pm_addr_entry *entry,
						    bool needs_id)
{
	struct mptcp_pm_addr_entry *match = NULL;
	struct sock *sk = (struct sock *)msk;
	struct mptcp_id_bitmap id_bitmap;
	struct mptcp_pm_addr_entry *e;
	bool addr_match = false;
	bool id_match = false;
	int ret = -EINVAL;

	bpf_bitmap_zero(&id_bitmap);

	bpf_spin_lock_bh(&msk->pm.lock);
	bpf_for_each(mptcp_address, e, msk) {
		addr_match = bpf_mptcp_addresses_equal(&e->addr, &entry->addr, true);
		if (addr_match && entry->addr.id == 0 && needs_id)
			entry->addr.id = e->addr.id;
		id_match = (e->addr.id == entry->addr.id);
		if (addr_match && id_match) {
			match = e;
			break;
		} else if (addr_match || id_match) {
			break;
		}
		bpf_set_bit(e->addr.id, &id_bitmap);
	}

	if (!match && !addr_match && !id_match) {
		/* Memory for the entry is allocated from the
		 * sock option buffer.
		 */
		e = bpf_pm_alloc_entry(sk, entry);
		if (!e) {
			ret = -ENOMEM;
			goto append_err;
		}

		if (!entry->addr.id && needs_id)
			entry->addr.id = bpf_next_bit(&id_bitmap);
		bpf_list_add_tail_rcu(&e->list, &msk->pm.userspace_pm_local_addr_list);
		msk->pm.local_addr_used++;
		ret = e->addr.id;
	} else if (match) {
		ret = entry->addr.id;
	}

append_err:
	bpf_spin_unlock_bh(&msk->pm.lock);
	return ret;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_address_announce, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local)
{
	int err;

	if (local->addr.id == 0 || !(local->flags & MPTCP_PM_ADDR_FLAG_SIGNAL))
		return -EINVAL;

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

static int mptcp_pm_remove_id_zero_address(struct mptcp_sock *msk)
{
	struct mptcp_rm_list list = { .nr = 0 };
	struct mptcp_subflow_context *subflow;
	bool has_id_0 = false;

	mptcp_for_each_subflow(msk, subflow) {
		subflow = bpf_core_cast(subflow, struct mptcp_subflow_context);
		if (subflow->local_id == 0) {
			has_id_0 = true;
			break;
		}
	}
	if (!has_id_0)
		return -EINVAL;

	list.ids[list.nr++] = 0;

	bpf_spin_lock_bh(&msk->pm.lock);
	mptcp_pm_remove_addr(msk, &list);
	bpf_spin_unlock_bh(&msk->pm.lock);

	return 0;
}

static struct mptcp_pm_addr_entry *
mptcp_userspace_pm_lookup_addr_by_id(struct mptcp_sock *msk, unsigned int id)
{
	struct mptcp_pm_addr_entry *entry;

	bpf_for_each(mptcp_address, entry, msk) {
		if (entry->addr.id == id)
			return entry;
	}
	return NULL;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_address_remove, struct mptcp_sock *msk, u8 id)
{
	struct sock *sk = (struct sock *)msk;
	struct mptcp_pm_addr_entry *entry;

	if (id == 0)
		return mptcp_pm_remove_id_zero_address(msk);

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr_by_id(msk, id);
	bpf_spin_unlock_bh(&msk->pm.lock);
	if (!entry)
		return -EINVAL;

	mptcp_pm_remove_addr_entry(msk, entry);

	bpf_spin_lock_bh(&msk->pm.lock);
	bpf_list_del_rcu(&entry->list);
	bpf_pm_free_entry(sk, entry);
	bpf_spin_unlock_bh(&msk->pm.lock);

	return 0;
}

static struct mptcp_pm_addr_entry *
mptcp_userspace_pm_lookup_addr(struct mptcp_sock *msk, const struct mptcp_addr_info *addr)
{
	struct mptcp_pm_addr_entry *entry;

	bpf_for_each(mptcp_address, entry, msk) {
		if (bpf_mptcp_addresses_equal(&entry->addr, addr, false))
			return entry;
	}
	return NULL;
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
	bpf_pm_free_entry(sk, entry);
	msk->pm.local_addr_used--;
	return 0;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_subflow_create, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local, struct mptcp_addr_info *remote)
{
	struct sock *sk = (struct sock *)msk;
	int err = -EINVAL;

	if (local->flags & MPTCP_PM_ADDR_FLAG_SIGNAL)
		return err;
	local->flags |= MPTCP_PM_ADDR_FLAG_SUBFLOW;

	if (!bpf_mptcp_pm_addr_families_match(sk, &local->addr, remote))
		return err;

	err = mptcp_userspace_pm_append_new_local_addr(msk, local, false);
	if (err < 0)
		return err;

	err = __mptcp_subflow_connect(sk, local, remote);
	bpf_spin_lock_bh(&msk->pm.lock);
	if (err)
		mptcp_userspace_pm_delete_local_addr(msk, local);
	else
		msk->pm.subflows++;
	bpf_spin_unlock_bh(&msk->pm.lock);

	return err;
}

static struct sock *mptcp_pm_find_ssk(struct mptcp_sock *msk,
				      const struct mptcp_addr_info *local,
				      const struct mptcp_addr_info *remote)
{
	struct mptcp_subflow_context *subflow;

	if (local->family != remote->family)
		return NULL;

	bpf_for_each(mptcp_subflow, subflow, msk) {
		const struct inet_sock *issk;
		struct sock *ssk;

		ssk = bpf_mptcp_subflow_tcp_sock(subflow);

		if (local->family != ssk->sk_family)
			continue;

		issk = bpf_core_cast(ssk, struct inet_sock);

		switch (ssk->sk_family) {
		case AF_INET:
			if (issk->inet_saddr != local->addr.s_addr ||
			    issk->inet_daddr != remote->addr.s_addr)
				continue;
			break;
		case AF_INET6: {
			const struct ipv6_pinfo *pinfo = bpf_inet6_sk(ssk);

			if (!bpf_ipv6_addr_equal(local, &pinfo->saddr) ||
			    !bpf_ipv6_addr_equal(remote, &ssk->sk_v6_daddr))
				continue;
			break;
		}
		default:
			continue;
		}

		if (issk->inet_sport == local->port &&
		    issk->inet_dport == remote->port)
			return ssk;
	}

	return NULL;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_subflow_destroy, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local, struct mptcp_addr_info *remote)
{
	struct sock *sk = (struct sock *)msk;
	int err = -EINVAL;
	struct sock *ssk;

	if (local->addr.family == AF_INET && bpf_ipv6_addr_v4mapped(remote)) {
		bpf_ipv6_addr_set_v4mapped(local->addr.addr.s_addr, remote);
		local->addr.family = AF_INET6;
	}
	if (remote->family == AF_INET && bpf_ipv6_addr_v4mapped(&local->addr)) {
		bpf_ipv6_addr_set_v4mapped(remote->addr.s_addr, &local->addr);
		remote->family = AF_INET6;
	}

	if (local->addr.family != remote->family)
		return err;

	if (!local->addr.port || !remote->port)
		return err;

	ssk = mptcp_pm_find_ssk(msk, &local->addr, remote);
	if (ssk) {
		struct mptcp_subflow_context *subflow = bpf_mptcp_subflow_ctx(ssk);

		bpf_spin_lock_bh(&msk->pm.lock);
		err = mptcp_userspace_pm_delete_local_addr(msk, local);
		bpf_spin_unlock_bh(&msk->pm.lock);
		mptcp_subflow_shutdown(sk, ssk, RCV_SHUTDOWN | SEND_SHUTDOWN);
		mptcp_close_ssk(sk, ssk, subflow);
	}

	return err;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_get_local_id, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local)
{
	const struct inet_sock *issk = bpf_core_cast((struct sock *)msk,
						     struct inet_sock);
	__be16 msk_sport = issk->inet_sport;
	struct mptcp_pm_addr_entry *entry;

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr(msk, &local->addr);
	bpf_spin_unlock_bh(&msk->pm.lock);
	if (entry)
		return entry->addr.id;

	if (local->addr.port == msk_sport)
		local->addr.port = 0;

	return mptcp_userspace_pm_append_new_local_addr(msk, local, true);
}

SEC("struct_ops")
u8 BPF_PROG(mptcp_pm_get_flags, struct mptcp_sock *msk,
	    struct mptcp_addr_info *skc)
{
	struct mptcp_pm_addr_entry *entry;
	u8 flags = 0;

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr(msk, skc);
	if (entry)
		flags = entry->flags;
	bpf_spin_unlock_bh(&msk->pm.lock);

	return flags;
}

SEC("struct_ops")
struct mptcp_pm_addr_entry *
BPF_PROG(mptcp_pm_get_addr, struct mptcp_sock *msk, u8 id)
{
	return mptcp_userspace_pm_lookup_addr_by_id(msk, id);
}

static int mptcp_userspace_pm_set_bitmap(struct mptcp_sock *msk,
					 struct mptcp_id_bitmap *bitmap)
{
	struct mptcp_pm_addr_entry *entry;

	mptcp_for_each_address(msk, entry) {
		entry = bpf_core_cast(entry, struct mptcp_pm_addr_entry);

		if (bpf_test_bit(entry->addr.id, bitmap))
			continue;

		bpf_set_bit(entry->addr.id, bitmap);
	}

	return 0;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_dump_addr, struct mptcp_sock *msk,
	     struct mptcp_id_bitmap *bitmap)
{
	return mptcp_userspace_pm_set_bitmap(msk, bitmap);
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_set_flags, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local, struct mptcp_addr_info *remote)
{
	struct mptcp_pm_addr_entry *entry;
	u8 bkup = 0;

	if (local->addr.family == AF_UNSPEC ||
	    remote->family == AF_UNSPEC)
		return -EINVAL;

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
	.address_announce	= (void *)mptcp_pm_address_announce,
	.address_remove		= (void *)mptcp_pm_address_remove,
	.subflow_create		= (void *)mptcp_pm_subflow_create,
	.subflow_destroy	= (void *)mptcp_pm_subflow_destroy,
	.get_local_id		= (void *)mptcp_pm_get_local_id,
	.get_flags		= (void *)mptcp_pm_get_flags,
	.get_addr		= (void *)mptcp_pm_get_addr,
	.dump_addr		= (void *)mptcp_pm_dump_addr,
	.set_flags		= (void *)mptcp_pm_set_flags,
	.init			= (void *)mptcp_pm_init,
	.release		= (void *)mptcp_pm_release,
	.type			= MPTCP_PM_TYPE_BPF,
};
