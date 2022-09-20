/* SPDX-License-Identifier: GPL-2.0
 * MPTCP Fast Open Mechanism. Copyright (c) 2021-2022, Dmytro SHYTYI
 */

#include "protocol.h"

int mptcp_setsockopt_sol_tcp_fastopen(struct mptcp_sock *msk, sockptr_t optval,
				      unsigned int optlen)
{
	struct sock *sk = (struct sock *)msk;
	struct net *net = sock_net(sk);
	int val;
	int ret;

	ret = 0;

	if (copy_from_sockptr(&val, optval, sizeof(val)))
		return -EFAULT;

	lock_sock(sk);

	if (val >= 0 && ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))) {
		tcp_fastopen_init_key_once(net);
		fastopen_queue_tune(sk, val);
	} else {
		ret = -EINVAL;
	}

	release_sock(sk);

	return ret;
}
