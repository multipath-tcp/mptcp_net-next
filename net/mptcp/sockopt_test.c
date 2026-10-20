// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>

#include "protocol.h"

#ifdef CONFIG_PROVE_LOCKING
static void mptcp_check_lockdep_class(struct kunit *test, struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct sock *ssk;

	ssk = READ_ONCE(msk->first);

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ssk);
	KUNIT_EXPECT_PTR_NE(test, sk->sk_lock.dep_map.key,
			    ssk->sk_lock.dep_map.key);
}
#endif

static void sock_release_wrapper(void *sock)
{
	sock_release(sock);
}

static void mptcp_test_reuseaddr(struct kunit *test, struct socket *sock)
{
	int reuse = 1;
	int err;

	err = sock_common_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				     KERNEL_SOCKPTR(&reuse), sizeof(reuse));
	KUNIT_EXPECT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, (int)sock->sk->sk_reuse, SK_CAN_REUSE);
}

static void mptcp_test_bindtodevice(struct kunit *test, struct socket *sock)
{
	struct net_device *lo = dev_get_by_name(&init_net, "lo");
	char ifname[IFNAMSIZ];
	int ifindex, err;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, lo);
	ifindex = lo->ifindex;
	strscpy(ifname, lo->name, sizeof(ifname));
	dev_put(lo);

	err = sock_common_setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
				     KERNEL_SOCKPTR(ifname),
				     strlen(ifname) + 1);
	KUNIT_EXPECT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, sock->sk->sk_bound_dev_if, ifindex);
}

static void mptcp_test_bindtoifindex(struct kunit *test, struct socket *sock)
{
	struct net_device *lo = dev_get_by_name(&init_net, "lo");
	int ifindex, err;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, lo);
	ifindex = lo->ifindex;
	dev_put(lo);

	err = sock_common_setsockopt(sock, SOL_SOCKET, SO_BINDTOIFINDEX,
				     KERNEL_SOCKPTR(&ifindex), sizeof(ifindex));
	KUNIT_EXPECT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, sock->sk->sk_bound_dev_if, ifindex);
}

static void mptcp_sockopt_test(struct kunit *test, sa_family_t family)
{
	struct socket *server_sock, *client_sock, *accepted_sock;
	struct msghdr send_msg = { 0 }, recv_msg = { 0 };
	struct sockaddr_storage addr = { 0 };
	struct kvec send_vec, recv_vec;
	char send_buf[] = "MPTCP";
	char recv_buf[32] = { 0 };
	int err, addrlen;

	if (family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(0);
		addr6->sin6_addr = in6addr_any;
		addrlen = sizeof(struct sockaddr_in6);
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(0);
		addr4->sin_addr.s_addr = htonl(INADDR_ANY);
		addrlen = sizeof(struct sockaddr_in);
	}

	err = sock_create_kern(&init_net, family, SOCK_STREAM, IPPROTO_MPTCP,
			       &server_sock);
	KUNIT_ASSERT_EQ(test, err, 0);
	err = kunit_add_action_or_reset(test, sock_release_wrapper,
					server_sock);
	KUNIT_ASSERT_EQ(test, err, 0);

	mptcp_test_reuseaddr(test, server_sock);

	mptcp_test_bindtodevice(test, server_sock);

	err = kernel_bind(server_sock, (struct sockaddr_unsized *)&addr,
			  addrlen);
	KUNIT_ASSERT_EQ(test, err, 0);

	err = kernel_getsockname(server_sock, (struct sockaddr *)&addr);
	KUNIT_ASSERT_EQ(test, err, addrlen);

	err = kernel_listen(server_sock, 5);
	KUNIT_ASSERT_EQ(test, err, 0);

	err = sock_create_kern(&init_net, family, SOCK_STREAM, IPPROTO_MPTCP,
			       &client_sock);
	KUNIT_ASSERT_EQ(test, err, 0);
	err = kunit_add_action_or_reset(test, sock_release_wrapper,
					client_sock);
	KUNIT_ASSERT_EQ(test, err, 0);

	mptcp_test_bindtoifindex(test, client_sock);

	err = kernel_connect(client_sock,
			     (struct sockaddr_unsized *)&addr,
			     addrlen, 0);
	KUNIT_ASSERT_EQ(test, err, 0);

	err = kernel_accept(server_sock, &accepted_sock, 0);
	KUNIT_ASSERT_EQ(test, err, 0);
	err = kunit_add_action_or_reset(test, sock_release_wrapper,
					accepted_sock);
	KUNIT_ASSERT_EQ(test, err, 0);

	send_vec.iov_base = send_buf;
	send_vec.iov_len = strlen(send_buf);
	err = kernel_sendmsg(client_sock, &send_msg, &send_vec, 1,
			     strlen(send_buf));
	KUNIT_ASSERT_EQ(test, err, (int)strlen(send_buf));

	recv_vec.iov_base = recv_buf;
	recv_vec.iov_len = sizeof(recv_buf);
	err = kernel_recvmsg(accepted_sock, &recv_msg, &recv_vec, 1,
			     sizeof(recv_buf), 0);
	KUNIT_ASSERT_EQ(test, err, (int)strlen(send_buf));

	KUNIT_EXPECT_STREQ(test, recv_buf, send_buf);

#ifdef CONFIG_PROVE_LOCKING
	mptcp_check_lockdep_class(test, client_sock->sk);
	mptcp_check_lockdep_class(test, accepted_sock->sk);
#endif
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
