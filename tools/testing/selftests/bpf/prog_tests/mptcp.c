// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020, Tessares SA. */
/* Copyright (c) 2022, SUSE. */

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"

#ifndef TCP_CA_NAME_MAX
#define TCP_CA_NAME_MAX	16
#endif

struct mptcp_storage {
	__u32 invoked;
	__u32 is_mptcp;
	__u32 token;
	char ca_name[TCP_CA_NAME_MAX];
};

static char monitor_log_path[64];

static int verify_tsk(int map_fd, int client_fd)
{
	char *msg = "plain TCP socket";
	int err, cfd = client_fd;
	struct mptcp_storage val;

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
	if (!ASSERT_GE(fd, 0, "Failed to open monitor_log_path"))
		return token;

	len = read(fd, buf, sizeof(buf));
	if (!ASSERT_GT(len, 0, "Failed to read monitor_log_path"))
		goto err;

	if (strncmp(buf, prefix, strlen(prefix))) {
		log_err("Invalid prefix %s", buf);
		goto err;
	}

	token = strtol(buf + strlen(prefix), NULL, 16);

err:
	close(fd);
	return token;
}

void get_msk_ca_name(char ca_name[])
{
	size_t len;
	int fd;

	fd = open("/proc/sys/net/ipv4/tcp_congestion_control", O_RDONLY);
	if (!ASSERT_GE(fd, 0, "Failed to open tcp_congestion_control"))
		return;

	len = read(fd, ca_name, TCP_CA_NAME_MAX);
	if (!ASSERT_GT(len, 0, "Failed to read ca_name"))
		goto err;

	if (len > 0 && ca_name[len - 1] == '\n')
		ca_name[len - 1] = '\0';

err:
	close(fd);
}

static int verify_msk(int map_fd, int client_fd)
{
	char *msg = "MPTCP subflow socket";
	int err, cfd = client_fd;
	struct mptcp_storage val;
	char ca_name[TCP_CA_NAME_MAX];
	__u32 token;

	token = get_msk_token();
	if (!ASSERT_GT(token, 0, "Unexpected token"))
		return -1;

	get_msk_ca_name(ca_name);

	err = bpf_map_lookup_elem(map_fd, &cfd, &val);
	if (!ASSERT_OK(err, "bpf_map_lookup_elem"))
		return err;

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

	if (strncmp(val.ca_name, ca_name, TCP_CA_NAME_MAX)) {
		log_err("Unexpected mptcp_sock.ca_name %s != %s",
			val.ca_name, ca_name);
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

	err += is_mptcp ? verify_msk(map_fd, client_fd) :
			  verify_tsk(map_fd, client_fd);

	close(client_fd);

out:
	bpf_object__close(obj);
	return err;
}

void test_base(void)
{
	char cmd[256], tmp_dir[] = "/tmp/XXXXXX";
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
	if (system("ip mptcp help 2>&1 | grep -q monitor")) {
		test__skip();
		goto close_cgroup_fd;
	}
	if (!ASSERT_OK_PTR(mkdtemp(tmp_dir), "mkdtemp"))
		goto close_cgroup_fd;
	snprintf(monitor_log_path, sizeof(monitor_log_path),
		 "%s/ip_mptcp_monitor", tmp_dir);
	snprintf(cmd, sizeof(cmd), "ip mptcp monitor > %s &", monitor_log_path);
	if (!ASSERT_OK(system(cmd), "ip mptcp monitor"))
		goto close_cgroup_fd;
	server_fd = start_mptcp_server(AF_INET, NULL, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_mptcp_server"))
		goto close_cgroup_fd;

	ASSERT_OK(run_test(cgroup_fd, server_fd, true), "run_test mptcp");

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
