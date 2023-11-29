// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2023, SUSE.
 */

#define pr_fmt(fmt) "MPTCP: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ftrace.h>
#include <net/sock.h>
#include <net/mptcp.h>
#include "protocol.h"
#include "mib.h"

static void mptcp_check_state(struct sock *sk, int oldstate, int state)
{
	switch (state) {
	case TCP_ESTABLISHED:
		if (oldstate != TCP_ESTABLISHED)
			MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_CURRESTAB);
		break;

	default:
		if (oldstate == TCP_ESTABLISHED)
			MPTCP_DEC_STATS(sock_net(sk), MPTCP_MIB_CURRESTAB);
	}
}

static void mptcp_state_callback(unsigned long ip,
				 unsigned long parent_ip,
				 struct ftrace_ops *op,
				 struct ftrace_regs *fregs)
{
	int oldstate, state;
	struct sock *sk;

	sk = (struct sock *)ftrace_regs_get_argument(fregs, 0);
	if (!sk)
		return;

	oldstate = sk->sk_state;
	state = (int)ftrace_regs_get_argument(fregs, 1);

	if (sk_is_mptcp(sk))
		mptcp_check_state(sk, oldstate, state);
}

static struct ftrace_ops mptcp_state_ops = {
	.func		= mptcp_state_callback,
	.flags		= FTRACE_OPS_FL_SAVE_REGS,
};

static __init int mptcp_ftrace_init(void)
{
	char *func_name = "tcp_set_state";
	int ret;

	ret = ftrace_set_filter(&mptcp_state_ops, func_name,
				strlen(func_name), 0);
	return ret ?: register_ftrace_function(&mptcp_state_ops);
}
late_initcall(mptcp_ftrace_init);
