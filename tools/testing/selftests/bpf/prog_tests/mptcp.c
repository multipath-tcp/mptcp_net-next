// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020, Tessares SA. */

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"

struct mptcp_storage {
	__u32 invoked;
	__u32 is_mptcp;
};

static int verify_sk(int map_fd, int client_fd, const char *msg, __u32 is_mptcp)
{
	int err = 0, cfd = client_fd;
	struct mptcp_storage val;

	if (is_mptcp == 1)
		return 0;

	if (CHECK_FAIL(bpf_map_lookup_elem(map_fd, &cfd, &val) < 0)) {
		perror("Failed to read socket storage");
		return -1;
	}

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
	int client_fd, prog_fd, map_fd;
	const char *file = "./mptcp.o";
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	int err = 0;

	obj = bpf_object__open(file);
	if (libbpf_get_error(obj))
		return -1;

	err = bpf_object__load(obj);
	if (err) {
		log_err("Failed to load BPF object");
		err = -1;
		goto close_bpf_object;
	}

	prog = bpf_object__next_program(obj, NULL);
	if (!prog) {
		log_err("Failed to get BPF program");
		err = -1;
		goto close_bpf_object;
	}

	prog_fd = bpf_program__fd(prog);

	map = bpf_object__next_map(obj, NULL);
	if (!map) {
		log_err("Failed to get BPF map");
		err = -1;
		goto close_bpf_object;
	}

	map_fd = bpf_map__fd(map);

	err = bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (err) {
		log_err("Failed to attach BPF program");
		err = -1;
		goto close_bpf_object;
	}

	client_fd = is_mptcp ? connect_to_mptcp_fd(server_fd, 0) :
			       connect_to_fd(server_fd, 0);
	if (client_fd < 0) {
		err = -1;
		goto close_client_fd;
	}

	err += is_mptcp ? verify_sk(map_fd, client_fd, "MPTCP subflow socket", 1) :
			  verify_sk(map_fd, client_fd, "plain TCP socket", 0);

close_client_fd:
	close(client_fd);

close_bpf_object:
	bpf_object__close(obj);
	return err;
}

void test_base(void)
{
	int server_fd, cgroup_fd;

	cgroup_fd = test__join_cgroup("/mptcp");
	if (CHECK_FAIL(cgroup_fd < 0))
		return;

	/* without MPTCP */
	server_fd = start_server(AF_INET, SOCK_STREAM, NULL, 0, 0);
	if (CHECK_FAIL(server_fd < 0))
		goto with_mptcp;

	CHECK_FAIL(run_test(cgroup_fd, server_fd, false));

	close(server_fd);

with_mptcp:
	/* with MPTCP */
	server_fd = start_mptcp_server(AF_INET, NULL, 0, 0);
	if (CHECK_FAIL(server_fd < 0))
		goto close_cgroup_fd;

	CHECK_FAIL(run_test(cgroup_fd, server_fd, true));

	close(server_fd);

close_cgroup_fd:
	close(cgroup_fd);
}

void test_mptcp(void)
{
	if (test__start_subtest("base"))
		test_base();
}
