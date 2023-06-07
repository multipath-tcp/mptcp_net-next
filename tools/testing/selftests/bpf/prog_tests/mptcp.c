// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020, Tessares SA. */
/* Copyright (c) 2022, SUSE. */

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"
#include "mptcp_sock.skel.h"
#include "mptcp_bpf_first.skel.h"
#include "mptcp_bpf_bkup.skel.h"
#include "mptcp_bpf_rr.skel.h"
#include "mptcp_bpf_red.skel.h"
#include "mptcp_bpf_burst.skel.h"
#include "mptcp_bpf_stale.skel.h"

char NS_TEST[32];

#ifndef TCP_CA_NAME_MAX
#define TCP_CA_NAME_MAX	16
#endif

struct mptcp_storage {
	__u32 invoked;
	__u32 is_mptcp;
	struct sock *sk;
	__u32 token;
	struct sock *first;
	char ca_name[TCP_CA_NAME_MAX];
};

static int verify_tsk(int map_fd, int client_fd)
{
	int err, cfd = client_fd;
	struct mptcp_storage val;

	err = bpf_map_lookup_elem(map_fd, &cfd, &val);
	if (!ASSERT_OK(err, "bpf_map_lookup_elem"))
		return err;

	if (!ASSERT_EQ(val.invoked, 1, "unexpected invoked count"))
		err++;

	if (!ASSERT_EQ(val.is_mptcp, 0, "unexpected is_mptcp"))
		err++;

	return err;
}

static void get_msk_ca_name(char ca_name[])
{
	size_t len;
	int fd;

	fd = open("/proc/sys/net/ipv4/tcp_congestion_control", O_RDONLY);
	if (!ASSERT_GE(fd, 0, "failed to open tcp_congestion_control"))
		return;

	len = read(fd, ca_name, TCP_CA_NAME_MAX);
	if (!ASSERT_GT(len, 0, "failed to read ca_name"))
		goto err;

	if (len > 0 && ca_name[len - 1] == '\n')
		ca_name[len - 1] = '\0';

err:
	close(fd);
}

static int verify_msk(int map_fd, int client_fd, __u32 token)
{
	char ca_name[TCP_CA_NAME_MAX];
	int err, cfd = client_fd;
	struct mptcp_storage val;

	if (!ASSERT_GT(token, 0, "invalid token"))
		return -1;

	get_msk_ca_name(ca_name);

	err = bpf_map_lookup_elem(map_fd, &cfd, &val);
	if (!ASSERT_OK(err, "bpf_map_lookup_elem"))
		return err;

	if (!ASSERT_EQ(val.invoked, 1, "unexpected invoked count"))
		err++;

	if (!ASSERT_EQ(val.is_mptcp, 1, "unexpected is_mptcp"))
		err++;

	if (!ASSERT_EQ(val.token, token, "unexpected token"))
		err++;

	if (!ASSERT_EQ(val.first, val.sk, "unexpected first"))
		err++;

	if (!ASSERT_STRNEQ(val.ca_name, ca_name, TCP_CA_NAME_MAX, "unexpected ca_name"))
		err++;

	return err;
}

static int run_test(int cgroup_fd, int server_fd, bool is_mptcp)
{
	int client_fd, prog_fd, map_fd, err;
	struct mptcp_sock *sock_skel;

	sock_skel = mptcp_sock__open_and_load();
	if (!ASSERT_OK_PTR(sock_skel, "skel_open_load"))
		return -EIO;

	err = mptcp_sock__attach(sock_skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	prog_fd = bpf_program__fd(sock_skel->progs._sockops);
	if (!ASSERT_GE(prog_fd, 0, "bpf_program__fd")) {
		err = -EIO;
		goto out;
	}

	map_fd = bpf_map__fd(sock_skel->maps.socket_storage_map);
	if (!ASSERT_GE(map_fd, 0, "bpf_map__fd")) {
		err = -EIO;
		goto out;
	}

	err = bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect to fd")) {
		err = -EIO;
		goto out;
	}

	err += is_mptcp ? verify_msk(map_fd, client_fd, sock_skel->bss->token) :
			  verify_tsk(map_fd, client_fd);

	close(client_fd);

out:
	mptcp_sock__destroy(sock_skel);
	return err;
}

static struct nstoken *create_netns(void)
{
	srand(time(NULL));
	snprintf(NS_TEST, sizeof(NS_TEST), "mptcp_ns_%d", rand());
	SYS(fail, "ip netns add %s", NS_TEST);
	SYS(fail, "ip -net %s link set dev lo up", NS_TEST);

	return open_netns(NS_TEST);
fail:
	return NULL;
}

static void cleanup_netns(struct nstoken *nstoken)
{
	if (nstoken)
		close_netns(nstoken);

	SYS_NOFAIL("ip netns del %s &> /dev/null", NS_TEST);
}

static void test_base(void)
{
	struct nstoken *nstoken = NULL;
	int server_fd, cgroup_fd;

	cgroup_fd = test__join_cgroup("/mptcp");
	if (!ASSERT_GE(cgroup_fd, 0, "test__join_cgroup"))
		return;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns"))
		goto fail;

	/* without MPTCP */
	server_fd = start_server(AF_INET, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto with_mptcp;

	ASSERT_OK(run_test(cgroup_fd, server_fd, false), "run_test tcp");

	close(server_fd);

with_mptcp:
	/* with MPTCP */
	server_fd = start_mptcp_server(AF_INET, NULL, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_mptcp_server"))
		goto fail;

	ASSERT_OK(run_test(cgroup_fd, server_fd, true), "run_test mptcp");

	close(server_fd);

fail:
	cleanup_netns(nstoken);

	close(cgroup_fd);
}

static const unsigned int total_bytes = 10 * 1024 * 1024;
static int stop, duration;

static void *server(void *arg)
{
	int lfd = (int)(long)arg, err = 0, fd;
	ssize_t nr_sent = 0, bytes = 0;
	char batch[1500];

	fd = accept(lfd, NULL, NULL);
	while (fd == -1) {
		if (errno == EINTR)
			continue;
		err = -errno;
		goto done;
	}

	if (settimeo(fd, 0)) {
		err = -errno;
		goto done;
	}

	while (bytes < total_bytes && !READ_ONCE(stop)) {
		nr_sent = send(fd, &batch,
			       MIN(total_bytes - bytes, sizeof(batch)), 0);
		if (nr_sent == -1 && errno == EINTR)
			continue;
		if (nr_sent == -1) {
			err = -errno;
			break;
		}
		bytes += nr_sent;
	}

	CHECK(bytes != total_bytes, "send", "%zd != %u nr_sent:%zd errno:%d\n",
	      bytes, total_bytes, nr_sent, errno);

done:
	if (fd >= 0)
		close(fd);
	if (err) {
		WRITE_ONCE(stop, 1);
		return ERR_PTR(err);
	}
	return NULL;
}

static void send_data(int lfd, int fd)
{
	ssize_t nr_recv = 0, bytes = 0;
	pthread_t srv_thread;
	void *thread_ret;
	char batch[1500];
	int err;

	WRITE_ONCE(stop, 0);

	err = pthread_create(&srv_thread, NULL, server, (void *)(long)lfd);
	if (CHECK(err != 0, "pthread_create", "err:%d errno:%d\n", err, errno))
		return;

	/* recv total_bytes */
	while (bytes < total_bytes && !READ_ONCE(stop)) {
		nr_recv = recv(fd, &batch,
			       MIN(total_bytes - bytes, sizeof(batch)), 0);
		if (nr_recv == -1 && errno == EINTR)
			continue;
		if (nr_recv == -1)
			break;
		bytes += nr_recv;
	}

	CHECK(bytes != total_bytes, "recv", "%zd != %u nr_recv:%zd errno:%d\n",
	      bytes, total_bytes, nr_recv, errno);

	WRITE_ONCE(stop, 1);

	pthread_join(srv_thread, &thread_ret);
	CHECK(IS_ERR(thread_ret), "pthread_join", "thread_ret:%ld",
	      PTR_ERR(thread_ret));
}

#define ADDR_1	"10.0.1.1"
#define ADDR_2	"10.0.1.2"

static struct nstoken *sched_init(char *flags, char *sched)
{
	struct nstoken *nstoken;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns"))
		goto fail;

	SYS(fail, "ip -net %s link add veth1 type veth peer name veth2", NS_TEST);
	SYS(fail, "ip -net %s addr add %s/24 dev veth1", NS_TEST, ADDR_1);
	SYS(fail, "ip -net %s link set dev veth1 up", NS_TEST);
	SYS(fail, "ip -net %s addr add %s/24 dev veth2", NS_TEST, ADDR_2);
	SYS(fail, "ip -net %s link set dev veth2 up", NS_TEST);
	SYS(fail, "ip -net %s mptcp endpoint add %s %s", NS_TEST, ADDR_2, flags);
	SYS(fail, "ip netns exec %s sysctl -qw net.mptcp.scheduler=%s", NS_TEST, sched);

	return nstoken;
fail:
	return NULL;
}

static int has_bytes_sent(char *addr)
{
	char cmd[128];

	snprintf(cmd, sizeof(cmd), "ip netns exec %s ss -it dst %s | grep -q bytes_sent:",
		 NS_TEST, addr);
	return system(cmd);
}

static void test_first(void)
{
	struct mptcp_bpf_first *first_skel;
	int server_fd, client_fd;
	struct nstoken *nstoken;
	struct bpf_link *link;

	first_skel = mptcp_bpf_first__open_and_load();
	if (!ASSERT_OK_PTR(first_skel, "bpf_first__open_and_load"))
		return;

	link = bpf_map__attach_struct_ops(first_skel->maps.first);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops")) {
		mptcp_bpf_first__destroy(first_skel);
		return;
	}

	nstoken = sched_init("subflow", "bpf_first");
	if (!ASSERT_OK_PTR(nstoken, "sched_init:bpf_first"))
		goto fail;
	server_fd = start_mptcp_server(AF_INET, ADDR_1, 0, 0);
	client_fd = connect_to_fd(server_fd, 0);

	send_data(server_fd, client_fd);
	ASSERT_OK(has_bytes_sent(ADDR_1), "has_bytes_sent addr_1");
	ASSERT_GT(has_bytes_sent(ADDR_2), 0, "has_bytes_sent addr_2");

	close(client_fd);
	close(server_fd);
fail:
	cleanup_netns(nstoken);
	bpf_link__destroy(link);
	mptcp_bpf_first__destroy(first_skel);
}

static void test_bkup(void)
{
	struct mptcp_bpf_bkup *bkup_skel;
	int server_fd, client_fd;
	struct nstoken *nstoken;
	struct bpf_link *link;

	bkup_skel = mptcp_bpf_bkup__open_and_load();
	if (!ASSERT_OK_PTR(bkup_skel, "bpf_bkup__open_and_load"))
		return;

	link = bpf_map__attach_struct_ops(bkup_skel->maps.bkup);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops")) {
		mptcp_bpf_bkup__destroy(bkup_skel);
		return;
	}

	nstoken = sched_init("subflow backup", "bpf_bkup");
	if (!ASSERT_OK_PTR(nstoken, "sched_init:bpf_bkup"))
		goto fail;
	server_fd = start_mptcp_server(AF_INET, ADDR_1, 0, 0);
	client_fd = connect_to_fd(server_fd, 0);

	send_data(server_fd, client_fd);
	ASSERT_OK(has_bytes_sent(ADDR_1), "has_bytes_sent addr_1");
	ASSERT_GT(has_bytes_sent(ADDR_2), 0, "has_bytes_sent addr_2");

	close(client_fd);
	close(server_fd);
fail:
	cleanup_netns(nstoken);
	bpf_link__destroy(link);
	mptcp_bpf_bkup__destroy(bkup_skel);
}

static void test_rr(void)
{
	struct mptcp_bpf_rr *rr_skel;
	int server_fd, client_fd;
	struct nstoken *nstoken;
	struct bpf_link *link;

	rr_skel = mptcp_bpf_rr__open_and_load();
	if (!ASSERT_OK_PTR(rr_skel, "bpf_rr__open_and_load"))
		return;

	link = bpf_map__attach_struct_ops(rr_skel->maps.rr);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops")) {
		mptcp_bpf_rr__destroy(rr_skel);
		return;
	}

	nstoken = sched_init("subflow", "bpf_rr");
	if (!ASSERT_OK_PTR(nstoken, "sched_init:bpf_rr"))
		goto fail;
	server_fd = start_mptcp_server(AF_INET, ADDR_1, 0, 0);
	client_fd = connect_to_fd(server_fd, 0);

	send_data(server_fd, client_fd);
	ASSERT_OK(has_bytes_sent(ADDR_1), "has_bytes_sent addr 1");
	ASSERT_OK(has_bytes_sent(ADDR_2), "has_bytes_sent addr 2");

	close(client_fd);
	close(server_fd);
fail:
	cleanup_netns(nstoken);
	bpf_link__destroy(link);
	mptcp_bpf_rr__destroy(rr_skel);
}

static void test_red(void)
{
	struct mptcp_bpf_red *red_skel;
	int server_fd, client_fd;
	struct nstoken *nstoken;
	struct bpf_link *link;

	red_skel = mptcp_bpf_red__open_and_load();
	if (!ASSERT_OK_PTR(red_skel, "bpf_red__open_and_load"))
		return;

	link = bpf_map__attach_struct_ops(red_skel->maps.red);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops")) {
		mptcp_bpf_red__destroy(red_skel);
		return;
	}

	nstoken = sched_init("subflow", "bpf_red");
	if (!ASSERT_OK_PTR(nstoken, "sched_init:bpf_red"))
		goto fail;
	server_fd = start_mptcp_server(AF_INET, ADDR_1, 0, 0);
	client_fd = connect_to_fd(server_fd, 0);

	send_data(server_fd, client_fd);
	ASSERT_OK(has_bytes_sent(ADDR_1), "has_bytes_sent addr 1");
	ASSERT_OK(has_bytes_sent(ADDR_2), "has_bytes_sent addr 2");

	close(client_fd);
	close(server_fd);
fail:
	cleanup_netns(nstoken);
	bpf_link__destroy(link);
	mptcp_bpf_red__destroy(red_skel);
}

static void test_burst(void)
{
	struct mptcp_bpf_burst *burst_skel;
	int server_fd, client_fd;
	struct nstoken *nstoken;
	struct bpf_link *link;

	burst_skel = mptcp_bpf_burst__open_and_load();
	if (!ASSERT_OK_PTR(burst_skel, "bpf_burst__open_and_load"))
		return;

	link = bpf_map__attach_struct_ops(burst_skel->maps.burst);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops")) {
		mptcp_bpf_burst__destroy(burst_skel);
		return;
	}

	nstoken = sched_init("subflow", "bpf_burst");
	if (!ASSERT_OK_PTR(nstoken, "sched_init:bpf_burst"))
		goto fail;
	server_fd = start_mptcp_server(AF_INET, ADDR_1, 0, 0);
	client_fd = connect_to_fd(server_fd, 0);

	send_data(server_fd, client_fd);
	ASSERT_OK(has_bytes_sent(ADDR_1), "has_bytes_sent addr 1");
	ASSERT_OK(has_bytes_sent(ADDR_2), "has_bytes_sent addr 2");

	close(client_fd);
	close(server_fd);
fail:
	cleanup_netns(nstoken);
	bpf_link__destroy(link);
	mptcp_bpf_burst__destroy(burst_skel);
}

static void test_stale(void)
{
	struct mptcp_bpf_stale *stale_skel;
	int server_fd, client_fd;
	struct nstoken *nstoken;
	struct bpf_link *link;

	stale_skel = mptcp_bpf_stale__open_and_load();
	if (!ASSERT_OK_PTR(stale_skel, "bpf_stale__open_and_load"))
		return;

	link = bpf_map__attach_struct_ops(stale_skel->maps.stale);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops")) {
		mptcp_bpf_stale__destroy(stale_skel);
		return;
	}

	nstoken = sched_init("subflow", "bpf_stale");
	if (!ASSERT_OK_PTR(nstoken, "sched_init:bpf_stale"))
		goto fail;
	server_fd = start_mptcp_server(AF_INET, ADDR_1, 0, 0);
	client_fd = connect_to_fd(server_fd, 0);

	send_data(server_fd, client_fd);
	ASSERT_OK(has_bytes_sent(ADDR_1), "has_bytes_sent addr_1");
	ASSERT_GT(has_bytes_sent(ADDR_2), 0, "has_bytes_sent addr_2");

	close(client_fd);
	close(server_fd);
fail:
	cleanup_netns(nstoken);
	bpf_link__destroy(link);
	mptcp_bpf_stale__destroy(stale_skel);
}

void test_mptcp(void)
{
	if (test__start_subtest("base"))
		test_base();
	if (test__start_subtest("first"))
		test_first();
	if (test__start_subtest("bkup"))
		test_bkup();
	if (test__start_subtest("rr"))
		test_rr();
	if (test__start_subtest("red"))
		test_red();
	if (test__start_subtest("burst"))
		test_burst();
	if (test__start_subtest("stale"))
		test_stale();
}
