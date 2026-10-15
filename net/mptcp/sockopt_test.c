// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>

#include "protocol.h"

static void mptcp_sockopt_reuseaddr(struct kunit *test)
{
	struct socket *sock;
	int err, reuse = 1;

	err = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_MPTCP,
			       &sock);
	KUNIT_ASSERT_EQ(test, err, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sock);

	err = sock_common_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				     KERNEL_SOCKPTR(&reuse), sizeof(reuse));

	KUNIT_EXPECT_EQ(test, err, 0);

	sock_release(sock);
}

static struct kunit_case mptcp_sockopt_test_cases[] = {
	KUNIT_CASE(mptcp_sockopt_reuseaddr),
	{}
};

static struct kunit_suite mptcp_sockopt_suite = {
	.name = "mptcp-sockopt",
	.test_cases = mptcp_sockopt_test_cases,
};

kunit_test_suite(mptcp_sockopt_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for MPTCP sockopt");
