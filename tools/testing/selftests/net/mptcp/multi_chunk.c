#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

#define TLS_PAYLOAD_MAX_LEN 16384
#define TEST_PORT 12345

static void chunked_sendfile(int cfd, int sfd,
			     size_t chunk_size,
			     size_t extra_payload_size)
{
	char buf[TLS_PAYLOAD_MAX_LEN];
	uint16_t test_payload_size;
	size_t recved = 0;
	size_t sent = 0;
	int size = 0;
	int ret;
	char filename[] = "/tmp/mytemp.XXXXXX";
	int fd = mkstemp(filename);
	off_t offset = 0;

	unlink(filename);
	if (fd <= 0) {
		perror("tempfile");
		exit(1);
	}
	if (chunk_size < 1) {
		perror("chunksize");
		exit(1);
	}

	test_payload_size = chunk_size + extra_payload_size;
	if (test_payload_size > TLS_PAYLOAD_MAX_LEN) {
		perror("payload_size");
		exit(1);
	}
	memset(buf, 1, test_payload_size);
	size = write(fd, buf, test_payload_size);
	if (size != test_payload_size) {
		perror("file write");
		exit(1);
	}
	fsync(fd);

	while (size > 0) {
		ret = sendfile(sfd, fd, &offset, chunk_size);
		if (ret <= 0)
			exit(1);
		size -= ret;
		sent += ret;
	}
	printf("[client] sent %zu bytes\n", sent);

	recved = recv(cfd, buf, test_payload_size, MSG_WAITALL);
	printf("[server] receieved %zu bytes\n", recved);

	if (recved != test_payload_size)
		exit(1);

	close(fd);
}

int main()
{
	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	int cfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	struct sockaddr_in addr = {0};
	socklen_t addrlen = sizeof(addr);

	printf("==== multi_chunk_sendfile MPTCP test ====\n");

	if (sfd < 0 || cfd < 0) {
		perror("socket");
		exit(1);
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(TEST_PORT);

	if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(1);
	}

	if (listen(sfd, 1) < 0) {
		perror("listen");
		exit(1);
	}

	if (getsockname(sfd, (struct sockaddr *)&addr, &addrlen) < 0) {
		perror("getsockname");
		exit(1);
	}

	if (connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		exit(1);
	}

	int nfd = accept(sfd, NULL, NULL);
	if (nfd < 0) {
		perror("accept");
		exit(1);
	}

	chunked_sendfile(cfd, nfd, 4096, 4096);
	chunked_sendfile(cfd, nfd, 4096, 0);
	chunked_sendfile(cfd, nfd, 4096, 1);
	chunked_sendfile(cfd, nfd, 4096, 2048);
	chunked_sendfile(cfd, nfd, 8192, 2048);
	chunked_sendfile(cfd, nfd, 4096, 8192);
	chunked_sendfile(cfd, nfd, 8192, 4096);
	chunked_sendfile(cfd, nfd, 12288, 1024);
	chunked_sendfile(cfd, nfd, 12288, 2000);
	chunked_sendfile(cfd, nfd, 15360, 100);
	chunked_sendfile(cfd, nfd, 15360, 300);
	chunked_sendfile(cfd, nfd, 1, 4096);
	chunked_sendfile(cfd, nfd, 2048, 4096);
	chunked_sendfile(cfd, nfd, 2048, 8192);
	chunked_sendfile(cfd, nfd, 4096, 8192);
	chunked_sendfile(cfd, nfd, 1024, 12288);
	chunked_sendfile(cfd, nfd, 2000, 12288);
	chunked_sendfile(cfd, nfd, 100, 15360);
	chunked_sendfile(cfd, nfd, 300, 15360);

	close(cfd);
	close(nfd);
	close(sfd);

	printf("==== test ends ====\n");
	return 0;
}
