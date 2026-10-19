// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>

#include "protocol.h"

#ifdef CONFIG_PROVE_LOCKING
static void mptcp_check_lockdep_class(struct kunit *test, struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct sock *ssk = msk->first;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ssk);
	KUNIT_EXPECT_PTR_NE(test,
			    sk->sk_lock.dep_map.key,
			    ssk->sk_lock.dep_map.key);
}
#endif

static void mptcp_sockopt_test(struct kunit *test, sa_family_t family)
{
	struct socket *server_sock, *client_sock, *accepted_sock;
	struct msghdr send_msg = { 0 }, recv_msg = { 0 };
	struct sockaddr_storage server_addr;
	struct kvec send_vec, recv_vec;
	struct sockaddr_storage addr;
	char send_buf[] = "MPTCP";
	char recv_buf[32] = { 0 };
	int err, reuse = 1;
	int addrlen;

	/* Initialize server address */
	memset(&addr, 0, sizeof(addr));
	if (family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(0);
		addr6->sin6_addr = in6addr_loopback;
		addrlen = sizeof(struct sockaddr_in6);
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(0);
		addr4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addrlen = sizeof(struct sockaddr_in);
	}

	/* Create server socket and test SO_REUSEADDR */
	err = sock_create_kern(&init_net, family, SOCK_STREAM, IPPROTO_MPTCP,
			       &server_sock);
	KUNIT_ASSERT_EQ(test, err, 0);

	err = sock_common_setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR,
				     KERNEL_SOCKPTR(&reuse), sizeof(reuse));
	KUNIT_EXPECT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, (int)server_sock->sk->sk_reuse, SK_CAN_REUSE);

	err = kernel_bind(server_sock, (struct sockaddr_unsized *)&addr,
			  addrlen);
	KUNIT_ASSERT_EQ(test, err, 0);

	/* Get the assigned port */
	err = kernel_getsockname(server_sock, (struct sockaddr *)&server_addr);
	KUNIT_ASSERT_EQ(test, err, addrlen);

	err = kernel_listen(server_sock, 5);
	KUNIT_ASSERT_EQ(test, err, 0);

	/* Create client socket and test SO_REUSEADDR */
	err = sock_create_kern(&init_net, family, SOCK_STREAM, IPPROTO_MPTCP,
			       &client_sock);
	KUNIT_ASSERT_EQ(test, err, 0);

	err = sock_common_setsockopt(client_sock, SOL_SOCKET, SO_REUSEADDR,
				     KERNEL_SOCKPTR(&reuse), sizeof(reuse));
	KUNIT_EXPECT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, (int)client_sock->sk->sk_reuse, SK_CAN_REUSE);

	/* Connect to server */
	err = kernel_connect(client_sock,
			     (struct sockaddr_unsized *)&server_addr,
			     addrlen, 0);
	KUNIT_ASSERT_EQ(test, err, 0);

	/* Accept connection on server */
	err = kernel_accept(server_sock, &accepted_sock, 0);
	KUNIT_ASSERT_EQ(test, err, 0);

	/* Send data from client */
	send_vec.iov_base = send_buf;
	send_vec.iov_len = strlen(send_buf);
	err = kernel_sendmsg(client_sock, &send_msg, &send_vec, 1,
			     strlen(send_buf));
	KUNIT_ASSERT_EQ(test, err, strlen(send_buf));

	/* Receive data on server */
	recv_vec.iov_base = recv_buf;
	recv_vec.iov_len = sizeof(recv_buf);
	err = kernel_recvmsg(accepted_sock, &recv_msg, &recv_vec, 1,
			     sizeof(recv_buf), 0);
	KUNIT_ASSERT_EQ(test, err, strlen(send_buf));

	/* Verify data */
	KUNIT_EXPECT_STREQ(test, recv_buf, send_buf);

#ifdef CONFIG_PROVE_LOCKING
	mptcp_check_lockdep_class(test, client_sock->sk);
	mptcp_check_lockdep_class(test, accepted_sock->sk);
#endif

	sock_release(accepted_sock);
	sock_release(client_sock);
	sock_release(server_sock);
}

static void mptcp_sockopt_test_v4(struct kunit *test)
{
	mptcp_sockopt_test(test, AF_INET);
}

#if IS_ENABLED(CONFIG_MPTCP_IPV6)
static void mptcp_sockopt_test_v6(struct kunit *test)
{
	mptcp_sockopt_test(test, AF_INET6);
}
#endif

static struct kunit_case mptcp_sockopt_test_cases[] = {
	KUNIT_CASE(mptcp_sockopt_test_v4),
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	KUNIT_CASE(mptcp_sockopt_test_v6),
#endif
	{}
};

static struct kunit_suite mptcp_sockopt_suite = {
	.name = "mptcp-sockopt",
	.test_cases = mptcp_sockopt_test_cases,
};

kunit_test_suite(mptcp_sockopt_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for MPTCP sockopt");
