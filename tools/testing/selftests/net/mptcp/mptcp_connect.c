// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

extern int optind;

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

static bool listen_mode;
static int  poll_timeout;

static const char *cfg_host;
static const char *cfg_port	= "12000";
static int cfg_sock_proto	= IPPROTO_MPTCP;


static void die_usage(void)
{
	fprintf(stderr, "Usage: mptcp_connect [-s MPTCP|TCP] [-p port] "
		"[ -l ] [ -t timeout ] connect_address\n");
	exit(1);
}

static const char *getxinfo_strerr(int err)
{
	if (err == EAI_SYSTEM)
		return strerror(errno);

	return gai_strerror(err);
}

static void xgetaddrinfo(const char *node, const char *service,
			 const struct addrinfo *hints,
			 struct addrinfo **res)
{
	int err = getaddrinfo(node, service, hints, res);

	if (err) {
		const char *errstr = getxinfo_strerr(err);

		fprintf(stderr, "Fatal: getaddrinfo(%s:%s): %s\n",
			node ? node : "", service ? service : "", errstr);
		exit(1);
	}
}

static int sock_listen_mptcp(const char * const listenaddr,
			     const char * const port)
{
	int sock;
	struct addrinfo hints = {
		.ai_protocol = IPPROTO_TCP,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_PASSIVE | AI_NUMERICHOST
	};

	hints.ai_family = AF_INET;

	struct addrinfo *a, *addr;
	int one = 1;

	xgetaddrinfo(listenaddr, port, &hints, &addr);

	for (a = addr; a; a = a->ai_next) {
		sock = socket(a->ai_family, a->ai_socktype, cfg_sock_proto);
		if (sock < 0)
			continue;

		if (-1 == setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one,
				     sizeof(one)))
			perror("setsockopt");

		if (bind(sock, a->ai_addr, a->ai_addrlen) == 0)
			break; /* success */

		perror("bind");
		close(sock);
		sock = -1;
	}

	freeaddrinfo(addr);

	if (sock < 0) {
		fprintf(stderr, "Could not create listen socket\n");
		return sock;
	}

	if (listen(sock, 20)) {
		perror("listen");
		close(sock);
		return -1;
	}

	return sock;
}

static int sock_connect_mptcp(const char * const remoteaddr,
			      const char * const port, int proto)
{
	struct addrinfo hints = {
		.ai_protocol = IPPROTO_TCP,
		.ai_socktype = SOCK_STREAM,
	};
	struct addrinfo *a, *addr;
	int sock = -1;

	hints.ai_family = AF_INET;

	xgetaddrinfo(remoteaddr, port, &hints, &addr);
	for (a = addr; a; a = a->ai_next) {
		sock = socket(a->ai_family, a->ai_socktype, proto);
		if (sock < 0) {
			perror("socket");
			continue;
		}

		if (connect(sock, a->ai_addr, a->ai_addrlen) == 0)
			break; /* success */

		perror("connect()");
		close(sock);
		sock = -1;
	}

	freeaddrinfo(addr);
	return sock;
}

static size_t do_rnd_write(const int fd, char *buf, const size_t len)
{
	size_t offset = 0;

	while (offset < len) {
		unsigned int do_w;
		size_t written;
		ssize_t bw;

		do_w = rand() & 0xffff;
		if (do_w == 0 || do_w > (len - offset))
			do_w = len - offset;

		bw = write(fd, buf + offset, do_w);
		if (bw < 0) {
			perror("write");
			return 0;
		}

		written = (size_t)bw;
		offset += written;
	}
	return offset;
}

static size_t do_write(const int fd, char *buf, const size_t len)
{
	size_t offset = 0;

	while (offset < len) {
		size_t written;
		ssize_t bw;

		bw = write(fd, buf + offset, len - offset);
		if (bw < 0) {
			perror("write");
			return 0;
		}

		written = (size_t)bw;
		offset += written;
	}

	return offset;
}

static ssize_t do_rnd_read(const int fd, char *buf, const size_t len)
{
	size_t cap = rand();

	cap &= 0xffff;

	if (cap == 0)
		cap = 1;
	else if (cap > len)
		cap = len;

	return read(fd, buf, cap);
}

static int copyfd_io(int infd, int peerfd, int outfd)
{
	struct pollfd fds = {
		.fd = peerfd,
		.events = POLLIN | POLLOUT,
	};

	for (;;) {
		char buf[8192];
		ssize_t len;

		if (fds.events == 0)
			break;

		switch (poll(&fds, 1, poll_timeout)) {
		case -1:
			if (errno == EINTR)
				continue;
			perror("poll");
			return 1;
		case 0:
			fprintf(stderr, "%s: poll timed out (events: "
				"POLLIN %u, POLLOUT %u)\n", __func__,
				fds.events & POLLIN, fds.events & POLLOUT);
			return 2;
		}

		if (fds.revents & POLLIN) {
			len = do_rnd_read(peerfd, buf, sizeof(buf));
			if (len == 0) {
				/* no more data to receive:
				 * peer has closed its write side
				 */
				fds.events &= ~POLLIN;

				if ((fds.events & POLLOUT) == 0)
					/* and nothing more to send */
					break;

			/* Else, still have data to transmit */
			} else if (len < 0) {
				perror("read");
				return 3;
			}

			do_write(outfd, buf, len);
		}

		if (fds.revents & POLLOUT) {
			len = do_rnd_read(infd, buf, sizeof(buf));
			if (len > 0) {
				if (!do_rnd_write(peerfd, buf, len))
					return 111;
			} else if (len == 0) {
				/* We have no more data to send. */
				fds.events &= ~POLLOUT;

				if ((fds.events & POLLIN) == 0)
					/* ... and peer also closed already */
					break;

				/* ... but we still receive.
				 * Close our write side.
				 */
				shutdown(peerfd, SHUT_WR);
			} else {
				if (errno == EINTR)
					continue;
				perror("read");
				return 4;
			}
		}
	}

	close(peerfd);
	return 0;
}

int main_loop_s(int listensock)
{
	struct sockaddr_storage ss;
	struct pollfd polls;
	socklen_t salen;
	int remotesock;

	polls.fd = listensock;
	polls.events = POLLIN;

	switch (poll(&polls, 1, poll_timeout)) {
	case -1:
		perror("poll");
		return 1;
	case 0:
		fprintf(stderr, "%s: timed out\n", __func__);
		close(listensock);
		return 2;
	}

	salen = sizeof(ss);
	remotesock = accept(listensock, (struct sockaddr *)&ss, &salen);
	if (remotesock >= 0) {
		copyfd_io(0, remotesock, 1);
		return 0;
	}

	perror("accept");

	return 1;
}

static void init_rng(void)
{
	int fd = open("/dev/urandom", O_RDONLY);
	unsigned int foo;

	if (fd > 0) {
		int ret = read(fd, &foo, sizeof(foo));

		if (ret < 0)
			srand(fd + foo);
		close(fd);
	}

	srand(foo);
}

int main_loop(void)
{
	int fd;

	/* listener is ready. */
	fd = sock_connect_mptcp(cfg_host, cfg_port, cfg_sock_proto);
	if (fd < 0)
		return 2;

	return copyfd_io(0, fd, 1);
}

int parse_proto(const char *proto)
{
	if (!strcasecmp(proto, "MPTCP"))
		return IPPROTO_MPTCP;
	if (!strcasecmp(proto, "TCP"))
		return IPPROTO_TCP;

	fprintf(stderr, "Unknown protocol: %s.", proto);
	die_usage();

	/* silence compiler warning */
	return 0;
}

static void parse_opts(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "lp:s:ht:")) != -1) {
		switch (c) {
		case 'l':
			listen_mode = true;
			break;
		case 'p':
			cfg_port = optarg;
			break;
		case 's':
			cfg_sock_proto = parse_proto(optarg);
			break;
		case 'h':
			die_usage();
			break;
		case 't':
			poll_timeout = atoi(optarg) * 1000;
			if (poll_timeout <= 0)
				poll_timeout = -1;
			break;
		}
	}

	if (optind + 1 != argc)
		die_usage();
	cfg_host = argv[optind];
}

int main(int argc, char *argv[])
{
	init_rng();

	parse_opts(argc, argv);

	if (listen_mode) {
		int fd = sock_listen_mptcp(cfg_host, cfg_port);

		if (fd < 0)
			return 1;

		return main_loop_s(fd);
	}

	return main_loop();
}
