// SPDX-License-Identifier: GPL-2.0
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

	/* Currently there is no easy way to get back the subflow sk from the MPTCP
	 * sk, thus we cannot access here the sk_storage associated to the subflow
	 * sk. Also, there is no sk_storage associated with the MPTCP sk since it
	 * does not trigger sockops events.
	 * We silently pass this situation at the moment.
	 */
	if (is_mptcp == 1)
		return 0;

	if (CHECK_FAIL(bpf_map_lookup_elem(map_fd, &cfd, &val) < 0)) {
		perror("Failed to read socket storage");
		return -1;
	}

	if (val.invoked != 1) {
		log_err("%s: unexpected invoked count %d != %d",
			msg, val.invoked, 1);
		err++;
	}

	if (val.is_mptcp != is_mptcp) {
		log_err("%s: unexpected bpf_tcp_sock.is_mptcp %d != %d",
			msg, val.is_mptcp, is_mptcp);
		err++;
	}

	return err;
}

static int run_test(int cgroup_fd, int server_fd, bool is_mptcp)
{
	int client_fd, prog_fd, map_fd, err;
	struct bpf_object *obj;
	struct bpf_map *map;

	struct bpf_prog_load_attr attr = {
		.prog_type = BPF_PROG_TYPE_SOCK_OPS,
		.file = "./mptcp.o",
		.expected_attach_type = BPF_CGROUP_SOCK_OPS,
	};

	err = bpf_prog_load_xattr(&attr, &obj, &prog_fd);
	if (err) {
		log_err("Failed to load BPF object");
		return -1;
	}

	map = bpf_map__next(NULL, obj);
	map_fd = bpf_map__fd(map);

	err = bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (err) {
		log_err("Failed to attach BPF program");
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

void test_mptcp(void)
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
