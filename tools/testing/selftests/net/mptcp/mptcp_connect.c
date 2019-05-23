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
#define IPPROTO_MPTCP 99
#endif

static const char *cfg_host;
static const char *cfg_port	= "12000";
static int cfg_server_proto	= IPPROTO_MPTCP;
static int cfg_client_proto	= IPPROTO_MPTCP;

static void die_usage(void)
{
	fprintf(stderr, "Usage: mptcp_connect [-c MPTCP|TCP] [-p port] "
	        "[-s MPTCP|TCP]\n");
	exit(-1);
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

		fprintf(stderr, "Fatal: getaddrinfo(%s:%s): %s\n", node ? node: "", service ? service: "", errstr);
	        exit(1);
	}
}

static int sock_listen_mptcp(const char * const listenaddr, const char * const port)
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

	for (a = addr; a != NULL ; a = a->ai_next) {
		sock = socket(a->ai_family, a->ai_socktype, cfg_server_proto);
		if (sock < 0) {
			perror("socket");
			continue;
		}

		if (-1 == setsockopt(sock, SOL_SOCKET,SO_REUSEADDR,&one,sizeof one))
			perror("setsockopt");


		if (bind(sock, a->ai_addr, a->ai_addrlen) == 0)
			break; /* success */

		perror("bind");
		close(sock);
		sock = -1;
	}

	if ((sock >= 0) && listen(sock ,20))
		perror("listen");

	freeaddrinfo(addr);
	return sock;
}

static int sock_connect_mptcp(const char * const remoteaddr, const char * const port, int proto)
{
	struct addrinfo hints = {
		.ai_protocol = IPPROTO_TCP,
		.ai_socktype = SOCK_STREAM,
	};
	struct addrinfo *a, *addr;
	int sock = -1;

	hints.ai_family = AF_INET;

	xgetaddrinfo(remoteaddr, port, &hints, &addr);
	for (a=addr; a != NULL; a = a->ai_next) {
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

static size_t do_write(const int fd, char *buf, const size_t len)
{
	size_t offset = 0;

	while (offset < len) {
		unsigned int do_w;
		size_t written;
		ssize_t bw;

		do_w = rand() & 0xffff;
		if (do_w == 0 || do_w > (len - offset))
			do_w = len - offset;

		bw = write(fd, buf+offset, do_w);
		if (bw < 0 ) {
			perror("write");
			return 0;
		}

		written = (size_t) bw;
		offset += written;
	}
	return offset;
}

static void copyfd_io(int peerfd)
{
	struct pollfd fds = { .events = POLLIN };

	fds.fd = peerfd;

	for (;;) {
		char buf[4096];
		ssize_t len;

		switch(poll(&fds, 1, -1)) {
		case -1:
			if (errno == EINTR)
				continue;
			perror("poll");
			return;
		case 0:
			/* should not happen, we requested infinite wait */
			fputs("Timed out?!", stderr);
			return;
		}

		if ((fds.revents & POLLIN) == 0)
			return;

		len = read(peerfd, buf, sizeof(buf));
		if (!len)
			return;
		if (len < 0) {
			if (errno == EINTR)
				continue;

			perror("read");
			return;
		}

		if (!do_write(peerfd, buf, len))
			return;

	}
}

int main_loop_s(int listensock)
{
	struct sockaddr_storage ss;
	socklen_t salen;
        int remotesock;

	salen = sizeof(ss);
	while ((remotesock = accept(listensock, (struct sockaddr *)&ss, &salen)) < 0)
		perror("accept");

	copyfd_io(remotesock);
	close(remotesock);

	return 0;
}

static void init_rng(void)
{
	int fd = open("/dev/urandom", O_RDONLY);
	unsigned int foo;

	if (fd > 0) {
		read(fd, &foo, sizeof(foo));
		close(fd);
	}

	srand(foo);
}

int main_loop()
{
	int pollfds = 2, timeout = -1;
	char start[32];
	int pipefd[2];
	ssize_t ret;
	int fd;

	if (pipe(pipefd)) {
		perror("pipe");
		exit(1);
	}

	switch (fork()) {
	case 0:
		close(pipefd[0]);

		init_rng();

		fd = sock_listen_mptcp(NULL, cfg_port);
		if (fd < 0)
			return -1;

		write(pipefd[1], "RDY\n", 4);
		main_loop_s(fd);
		exit(1);
	case -1:
		perror("fork");
		return -1;
	default:
		close(pipefd[1]);
		break;
	}

	init_rng();
	ret = read(pipefd[0], start, (int)sizeof(start));
	if (ret < 0) {
		perror("read");
		return -1;
	}

	if (ret != 4 || strcmp(start, "RDY\n"))
		return -1;

	/* listener is ready. */
	fd = sock_connect_mptcp(cfg_host, cfg_port, cfg_client_proto);
	if (fd < 0)
		return -1;

	for (;;) {
		struct pollfd fds[2];
		char buf[4096];
		ssize_t len;

		fds[0].fd = fd;
		fds[0].events = POLLIN;
		fds[1].fd = 0;
		fds[1].events = POLLIN;
		fds[1].revents = 0;

		switch (poll(fds, pollfds, timeout)) {
		case -1:
			if (errno == EINTR)
				continue;
			perror("poll");
			return -1;
		case 0:
			close(fd);
			return 0;
		}

		if (fds[0].revents & POLLIN) {
			unsigned int blen = rand();

			blen %= sizeof(buf);

			++blen;
			len = read(fd, buf, blen);
			if (len < 0) {
				perror("read");
				return -1;
			}

			if (len > blen) {
				fprintf(stderr, "read returned more data than buffer length\n");
				len = blen;
			}

			write(1, buf, len);
		}
		if (fds[1].revents & POLLIN) {
			len = read(0, buf, sizeof(buf));
			if (len == 0) {
				pollfds = 1;
				timeout = 1000;
				continue;
			}

			if (len < 0) {
				perror("read");
				break;
			}

			do_write(fd, buf, len);
		}
	}

	return 1;
}

int parse_proto(const char *proto)
{
	if (!strcasecmp(proto, "MPTCP"))
		return IPPROTO_MPTCP;
	if (!strcasecmp(proto, "TCP"))
		return IPPROTO_TCP;
	die_usage();

	/* silence compiler warning */
	return 0;
}

static void parse_opts(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "c:p:s:h")) != -1) {
		switch (c) {
		case 'c':
			cfg_client_proto = parse_proto(optarg);
			break;
		case 'p':
			cfg_port = optarg;
			break;
		case 's':
			cfg_server_proto = parse_proto(optarg);
			break;
		case 'h':
			die_usage();
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
	return main_loop();
}
