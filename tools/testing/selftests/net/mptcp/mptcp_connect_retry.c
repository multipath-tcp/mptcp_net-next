// SPDX-License-Identifier: GPL-2.0
/*
 * Same-fd MPTCP connect() retry helper.
 *
 * Optionally fails an initial connect() with the wrong address family, then
 * connects to the given IPv4 destination and checks MPTCP_INFO flags.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <linux/mptcp.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif
#ifndef SOL_MPTCP
#define SOL_MPTCP 284
#endif

static void die_perror(const char *msg)
{
	perror(msg);
	exit(1);
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-e] [-c] <ipv4> <port>\n"
		"  -e  first connect() with a wrong sin_family (EAFNOSUPPORT)\n"
		"  -c  clear net.mptcp.blackhole_timeout after the failed connect\n",
		argv0);
	exit(1);
}

static int getsockopt_mptcp_info(int fd, struct mptcp_info *info)
{
	socklen_t olen = sizeof(*info);

	memset(info, 0, sizeof(*info));
	return getsockopt(fd, SOL_MPTCP, MPTCP_INFO, info, &olen);
}

static int get_mptcp_info(int fd, struct mptcp_info *info)
{
	if (!getsockopt_mptcp_info(fd, info))
		return 0;

	/* Fallback sockets forward SOL_MPTCP to TCP. */
	if (errno == EOPNOTSUPP) {
		info->mptcpi_flags = MPTCP_INFO_FLAG_FALLBACK;
		return 0;
	}
	return -1;
}

static int clear_blackhole_timeout(void)
{
	ssize_t n;
	int fd;

	fd = open("/proc/sys/net/mptcp/blackhole_timeout", O_WRONLY);
	if (fd < 0)
		return -1;

	n = write(fd, "0\n", 2);
	close(fd);
	return n == 2 ? 0 : -1;
}

static int connect_wrong_family(int fd)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET6,
	};

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
		fprintf(stderr, "wrong-family connect() unexpectedly succeeded\n");
		return -1;
	}
	if (errno != EAFNOSUPPORT) {
		fprintf(stderr, "wrong-family connect(): unexpected errno %d (%s)\n",
			errno, strerror(errno));
		return -1;
	}
	return 0;
}

static int connect_ipv4(int fd, const char *ip, unsigned short port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};

	if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
		fprintf(stderr, "invalid IPv4 address %s\n", ip);
		return -1;
	}
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "connect(%s:%u): %s\n", ip, port, strerror(errno));
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	bool fail_first = false, clear_bh = false;
	struct mptcp_info after_fail = { 0 }, after_ok, probe;
	bool fail_fb = false, ok_fb, ok_key;
	const char *ip;
	unsigned short port;
	int fd, opt, err = 0;
	char buf[128];
	ssize_t n;

	while ((opt = getopt(argc, argv, "ec")) != -1) {
		switch (opt) {
		case 'e':
			fail_first = true;
			break;
		case 'c':
			clear_bh = true;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (optind + 2 != argc)
		usage(argv[0]);

	ip = argv[optind];
	port = atoi(argv[optind + 1]);
	if (!port)
		usage(argv[0]);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (fd < 0)
		die_perror("socket(IPPROTO_MPTCP)");

	if (getsockopt_mptcp_info(fd, &probe)) {
		fprintf(stderr, "getsockopt(MPTCP_INFO): %s\n", strerror(errno));
		close(fd);
		return 2;
	}

	if (fail_first && connect_wrong_family(fd)) {
		close(fd);
		return 1;
	}

	if (fail_first) {
		if (get_mptcp_info(fd, &after_fail)) {
			fprintf(stderr, "getsockopt(MPTCP_INFO) after fail: %s\n",
				strerror(errno));
			close(fd);
			return 2;
		}
		fail_fb = after_fail.mptcpi_flags & MPTCP_INFO_FLAG_FALLBACK;
	}

	if (clear_bh && clear_blackhole_timeout()) {
		fprintf(stderr, "unable to clear blackhole_timeout: %s\n",
			strerror(errno));
		close(fd);
		return 1;
	}

	if (connect_ipv4(fd, ip, port)) {
		close(fd);
		return 1;
	}

	if (get_mptcp_info(fd, &after_ok)) {
		fprintf(stderr, "getsockopt(MPTCP_INFO) after connect: %s\n",
			strerror(errno));
		close(fd);
		return 2;
	}

	if (write(fd, "retry\n", 6) < 0)
		perror("write");
	shutdown(fd, SHUT_WR);
	do {
		n = read(fd, buf, sizeof(buf));
	} while (n > 0);
	close(fd);

	ok_fb = after_ok.mptcpi_flags & MPTCP_INFO_FLAG_FALLBACK;
	ok_key = after_ok.mptcpi_flags & MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED;

	if (fail_fb) {
		fprintf(stderr, "fallback still set after failed connect()\n");
		err = 1;
	}
	if (ok_fb || !ok_key) {
		fprintf(stderr, "second connect() did not complete MPTCP handshake\n");
		err = 1;
	}

	return err;
}
