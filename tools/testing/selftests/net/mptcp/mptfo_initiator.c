#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <string.h>
#include <signal.h>

#define SERVER_PORT 7003

int main(int argc, char *argv[])
{
	unsigned char valsyn[3] = "abc";
	struct sockaddr_in daddr;
	char *valend = "fff";
	char *val1 = "zz1";
	char *val2 = "zz2";
	char *val3 = "zz3";
	int sock_fd = -1;
	int ret;

	memset(&daddr, 0, sizeof(daddr));
	inet_pton(AF_INET, "10.10.0.2", &daddr.sin_addr);
	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(SERVER_PORT);

	sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);

	ret = sendto(sock_fd, valsyn, 3, MSG_FASTOPEN, (struct sockaddr *) &daddr, sizeof(daddr));
	ret = write(sock_fd, val1, 3);
	ret = write(sock_fd, val2, 3);
	ret = write(sock_fd, val2, 3);
	ret = write(sock_fd, val2, 3);
	ret = write(sock_fd, val3, 3);
	ret = write(sock_fd, valend, 3);

	close(sock_fd);
	return EXIT_SUCCESS;
}
