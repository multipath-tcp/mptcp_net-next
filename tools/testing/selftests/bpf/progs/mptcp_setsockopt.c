#include "bpf_tracing_net.h"
#include "mptcp_bpf.h"

#ifndef TCP_INQ
#define TCP_INQ 36
#endif

int connect_cb_inq_ret;
int connect_cb_cc_ret;

char cc_reno[TCP_CA_NAME_MAX] = "reno";

SEC("sockops")
int mptcp_connect_cb(struct bpf_sock_ops *skops)
{
	struct bpf_sock *sk = skops->sk;
	int one = 1;

	if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
		return 1;

	if (!sk || sk->protocol != IPPROTO_MPTCP)
		return 1;

	connect_cb_inq_ret =
		bpf_setsockopt(skops, SOL_TCP, TCP_INQ, &one, sizeof(one));
	connect_cb_cc_ret =
		bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION,
			       cc_reno, sizeof(cc_reno));

	return 1;
}
