// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020, Tessares SA. */
/* Copyright (c) 2022, SUSE. */

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"

struct mptcp_storage {
	__u32 invoked;
	__u32 is_mptcp;
};

static int verify_sk(int map_fd, int client_fd, const char *msg, __u32 is_mptcp)
{
	int err, cfd = client_fd;
	struct mptcp_storage val;

	if (is_mptcp == 1)
		return 0;

	err = bpf_map_lookup_elem(map_fd, &cfd, &val);
	if (!ASSERT_OK(err, "bpf_map_lookup_elem"))
		return err;

	if (val.invoked != 1) {
		log_err("%s: unexpected invoked count %d != 1",
			msg, val.invoked);
		err++;
	}

	if (val.is_mptcp != 0) {
		log_err("%s: unexpected bpf_tcp_sock.is_mptcp %d != 0",
			msg, val.is_mptcp);
		err++;
	}

	return err;
}

static int run_test(int cgroup_fd, int server_fd, bool is_mptcp)
{
	int client_fd, prog_fd, map_fd, err;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;

	obj = bpf_object__open("./mptcp_sock.o");
	if (libbpf_get_error(obj))
		return -EIO;

	err = bpf_object__load(obj);
	if (!ASSERT_OK(err, "bpf_object__load"))
		goto out;

	prog = bpf_object__find_program_by_name(obj, "_sockops");
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name")) {
		err = -EIO;
		goto out;
	}

	prog_fd = bpf_program__fd(prog);
	if (!ASSERT_GE(prog_fd, 0, "bpf_program__fd")) {
		err = -EIO;
		goto out;
	}

	map = bpf_object__find_map_by_name(obj, "socket_storage_map");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name")) {
		err = -EIO;
		goto out;
	}

	map_fd = bpf_map__fd(map);
	if (!ASSERT_GE(map_fd, 0, "bpf_map__fd")) {
		err = -EIO;
		goto out;
	}

	err = bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	client_fd = is_mptcp ? connect_to_mptcp_fd(server_fd, 0) :
			       connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect to fd")) {
		err = -EIO;
		goto out;
	}

	err += is_mptcp ? verify_sk(map_fd, client_fd, "MPTCP subflow socket", 1) :
			  verify_sk(map_fd, client_fd, "plain TCP socket", 0);

	close(client_fd);

out:
	bpf_object__close(obj);
	return err;
}

void test_base(void)
{
	int server_fd, cgroup_fd;

	cgroup_fd = test__join_cgroup("/mptcp");
	if (!ASSERT_GE(cgroup_fd, 0, "test__join_cgroup"))
		return;

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
		goto close_cgroup_fd;

	ASSERT_OK(run_test(cgroup_fd, server_fd, true), "run_test mptcp");

	close(server_fd);

close_cgroup_fd:
	close(cgroup_fd);
}

void test_mptcp(void)
{
	if (test__start_subtest("base"))
		test_base();
}
