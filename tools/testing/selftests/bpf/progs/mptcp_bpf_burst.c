// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, SUSE. */

#include "mptcp_bpf.h"
#include <bpf/bpf_tracing.h>
#include <limits.h>

char _license[] SEC("license") = "GPL";

#define MPTCP_SEND_BURST_SIZE	65428

#define min(a, b) ((a) < (b) ? (a) : (b))

#define SSK_MODE_ACTIVE	0
#define SSK_MODE_BACKUP	1
#define SSK_MODE_MAX	2

struct bpf_subflow_send_info {
	__u8 subflow_id;
	__u64 linger_time;
};

extern void mptcp_set_timeout(struct sock *sk) __ksym;
extern __u64 mptcp_wnd_end(const struct mptcp_sock *msk) __ksym;
extern bool tcp_stream_memory_free(const struct sock *sk, int wake) __ksym;
extern bool bpf_mptcp_subflow_queues_empty(struct sock *sk) __ksym;
extern void mptcp_pm_subflow_chk_stale(const struct mptcp_sock *msk, struct sock *ssk) __ksym;

static __always_inline __u64 div_u64(__u64 dividend, __u32 divisor)
{
	return dividend / divisor;
}

static __always_inline bool tcp_write_queue_empty(struct sock *sk)
{
	const struct tcp_sock *tp = bpf_skc_to_tcp_sock(sk);

	return tp ? tp->write_seq == tp->snd_nxt : true;
}

static __always_inline bool tcp_rtx_and_write_queues_empty(struct sock *sk)
{
	return bpf_mptcp_subflow_queues_empty(sk) && tcp_write_queue_empty(sk);
}

static __always_inline bool __sk_stream_memory_free(const struct sock *sk, int wake)
{
	if (sk->sk_wmem_queued >= sk->sk_sndbuf)
		return false;

	return tcp_stream_memory_free(sk, wake);
}

static __always_inline bool sk_stream_memory_free(const struct sock *sk)
{
	return __sk_stream_memory_free(sk, 0);
}

static struct mptcp_subflow_context *
mptcp_lookup_subflow_by_id(struct mptcp_sock *msk, unsigned int id)
{
	struct mptcp_subflow_context *subflow;

	bpf_for_each(mptcp_subflow, subflow, msk) {
		if (subflow->subflow_id == id)
			return subflow;
	}

	return NULL;
}

SEC("struct_ops")
void BPF_PROG(mptcp_sched_burst_init, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
void BPF_PROG(mptcp_sched_burst_release, struct mptcp_sock *msk)
{
}

static int bpf_burst_get_send(struct mptcp_sock *msk)
{
	struct bpf_subflow_send_info send_info[SSK_MODE_MAX];
	struct mptcp_subflow_context *subflow;
	struct sock *sk = (struct sock *)msk;
	__u32 pace, burst, wmem;
	int i, nr_active = 0;
	__u64 linger_time;
	struct sock *ssk;

	/* pick the subflow with the lower wmem/wspace ratio */
	for (i = 0; i < SSK_MODE_MAX; ++i) {
		send_info[i].subflow_id = MPTCP_SUBFLOWS_MAX;
		send_info[i].linger_time = -1;
	}

	bpf_for_each(mptcp_subflow, subflow, msk) {
		bool backup = subflow->backup || subflow->request_bkup;

		ssk = bpf_mptcp_subflow_tcp_sock(subflow);
		if (!mptcp_subflow_active(subflow))
			continue;

		nr_active += !backup;
		pace = subflow->avg_pacing_rate;
		if (!pace) {
			/* init pacing rate from socket */
			subflow->avg_pacing_rate = ssk->sk_pacing_rate;
			pace = subflow->avg_pacing_rate;
			if (!pace)
				continue;
		}

		linger_time = div_u64((__u64)ssk->sk_wmem_queued << 32, pace);
		if (linger_time < send_info[backup].linger_time) {
			send_info[backup].subflow_id = subflow->subflow_id;
			send_info[backup].linger_time = linger_time;
		}
	}
	mptcp_set_timeout(sk);

	/* pick the best backup if no other subflow is active */
	if (!nr_active)
		send_info[SSK_MODE_ACTIVE].subflow_id = send_info[SSK_MODE_BACKUP].subflow_id;

	subflow = mptcp_lookup_subflow_by_id(msk, send_info[SSK_MODE_ACTIVE].subflow_id);
	if (!subflow)
		return -1;
	ssk = bpf_mptcp_subflow_tcp_sock(subflow);
	if (!ssk || !sk_stream_memory_free(ssk))
		return -1;

	burst = min(MPTCP_SEND_BURST_SIZE, mptcp_wnd_end(msk) - msk->snd_nxt);
	wmem = ssk->sk_wmem_queued;
	if (!burst)
		goto out;

	subflow->avg_pacing_rate = div_u64((__u64)subflow->avg_pacing_rate * wmem +
					   ssk->sk_pacing_rate * burst,
					   burst + wmem);
	msk->snd_burst = burst;

out:
	mptcp_subflow_set_scheduled(subflow, true);
	return 0;
}

static int bpf_burst_get_retrans(struct mptcp_sock *msk)
{
	struct sock *backup = NULL, *pick = NULL;
	struct mptcp_subflow_context *subflow;
	int min_stale_count = INT_MAX;

	bpf_for_each(mptcp_subflow, subflow, msk) {
		struct sock *ssk = bpf_mptcp_subflow_tcp_sock(subflow);

		if (!mptcp_subflow_active(subflow))
			continue;

		/* still data outstanding at TCP level? skip this */
		if (!tcp_rtx_and_write_queues_empty(ssk)) {
			mptcp_pm_subflow_chk_stale(msk, ssk);
			min_stale_count = min(min_stale_count, subflow->stale_count);
			continue;
		}

		if (subflow->backup || subflow->request_bkup) {
			if (!backup)
				backup = ssk;
			continue;
		}

		if (!pick)
			pick = ssk;
	}

	if (pick)
		goto out;
	pick = min_stale_count > 1 ? backup : NULL;

out:
	if (!pick)
		return -1;
	subflow = bpf_mptcp_subflow_ctx(pick);
	if (!subflow)
		return -1;
	mptcp_subflow_set_scheduled(subflow, true);
	return 0;
}

SEC("struct_ops")
int BPF_PROG(bpf_burst_get_subflow, struct mptcp_sock *msk,
	     struct mptcp_sched_data *data)
{
	if (data->reinject)
		return bpf_burst_get_retrans(msk);
	return bpf_burst_get_send(msk);
}

SEC(".struct_ops")
struct mptcp_sched_ops burst = {
	.init		= (void *)mptcp_sched_burst_init,
	.release	= (void *)mptcp_sched_burst_release,
	.get_subflow	= (void *)bpf_burst_get_subflow,
	.name		= "bpf_burst",
};
