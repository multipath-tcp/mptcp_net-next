// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020, Tessares SA. */

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"

struct mptcp_storage {
	__u32 invoked;
	__u32 is_mptcp;
	__u32 token;
};

static char monitor_log_path[64];

static int verify_tsk(int map_fd, int client_fd)
{
	char *msg = "plain TCP socket";
	int err = 0, cfd = client_fd;
	struct mptcp_storage val;

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

/*
 * Parse the token from the output of 'ip mptcp monitor':
 *
 * [       CREATED] token=3ca933d3 remid=0 locid=0 saddr4=127.0.0.1 ...
 * [       CREATED] token=2ab57040 remid=0 locid=0 saddr4=127.0.0.1 ...
 */
static __u32 get_msk_token(void)
{
	char *prefix = "[       CREATED] token=";
	char buf[BUFSIZ] = {};
	__u32 token = 0;
	ssize_t len;
	int fd;

	sync();

	fd = open(monitor_log_path, O_RDONLY);
	if (CHECK_FAIL(fd < 0)) {
		log_err("Failed to open %s", monitor_log_path);
		return token;
	}

	len = read(fd, buf, sizeof(buf));
	if (CHECK_FAIL(len < 0)) {
		log_err("Failed to read %s", monitor_log_path);
		goto err;
	}

	if (strncmp(buf, prefix, strlen(prefix))) {
		log_err("Invalid prefix %s", buf);
		goto err;
	}

	token = strtol(buf + strlen(prefix), NULL, 16);

err:
	close(fd);
	return token;
}

static int verify_msk(int map_fd, int client_fd)
{
	char *msg = "MPTCP subflow socket";
	int err = 0, cfd = client_fd;
	struct mptcp_storage val;
	__u32 token;

	token = get_msk_token();
	if (token <= 0) {
		log_err("Unexpected token %x", token);
		return -1;
	}

	if (CHECK_FAIL(bpf_map_lookup_elem(map_fd, &cfd, &val) < 0)) {
		perror("Failed to read socket storage");
		return -1;
	}

	if (val.invoked != 1) {
		log_err("%s: unexpected invoked count %d != 1",
			msg, val.invoked);
		err++;
	}

	if (val.is_mptcp != 1) {
		log_err("%s: unexpected bpf_tcp_sock.is_mptcp %d != 1",
			msg, val.is_mptcp);
		err++;
	}

	if (val.token != token) {
		log_err("Unexpected mptcp_sock.token %x != %x",
			val.token, token);
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

	err += is_mptcp ? verify_msk(map_fd, client_fd) :
			  verify_tsk(map_fd, client_fd);

close_client_fd:
	close(client_fd);

close_bpf_object:
	bpf_object__close(obj);
	return err;
}

void test_base(void)
{
	char cmd[256], tmp_dir[] = "/tmp/XXXXXX";
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
	if (CHECK_FAIL(!mkdtemp(tmp_dir)))
		goto close_cgroup_fd;
	snprintf(monitor_log_path, sizeof(monitor_log_path),
		 "%s/ip_mptcp_monitor", tmp_dir);
	snprintf(cmd, sizeof(cmd), "ip mptcp monitor > %s &", monitor_log_path);
	if (CHECK_FAIL(system(cmd)))
		goto close_cgroup_fd;
	server_fd = start_mptcp_server(AF_INET, NULL, 0, 0);
	if (CHECK_FAIL(server_fd < 0))
		goto close_cgroup_fd;

	CHECK_FAIL(run_test(cgroup_fd, server_fd, true));

	close(server_fd);
	snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp_dir);
	system(cmd);

close_cgroup_fd:
	close(cgroup_fd);
}

void test_mptcp(void)
{
	if (test__start_subtest("base"))
		test_base();
}
