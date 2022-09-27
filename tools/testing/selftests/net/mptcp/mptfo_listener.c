// SPDX-License-Identifier: GPL-2.0

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/in.h>
#include <netinet/tcp.h>

#define CLIENT_QUEUE_LEN 10
#define SERVER_PORT 7003

int main(void)
{
	int listen_sock_fd = -1, client_sock_fd = -1;
	char str_addr[INET6_ADDRSTRLEN];
	struct sockaddr_in server_addr;
	int ret, flag;
	int qlen = 5;
	char ch;

	server_addr.sin_family = AF_INET;
	inet_pton(AF_INET, "10.10.0.2", &server_addr.sin_addr);
	server_addr.sin_port = htons(SERVER_PORT);

	/* Create socket for listening (client requests) */
	listen_sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (listen_sock_fd == -1) {
		perror("socket()server");
		return EXIT_FAILURE;
	}

	/* Set socket to reuse address */
	flag = 1;
	ret = setsockopt(listen_sock_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
	if (ret == -1) {
		perror("setsockopt()");
		return EXIT_FAILURE;
	}

	ret = setsockopt(listen_sock_fd, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
	if (ret == -1) {
		perror("setsockopt()TCP_FASTOPEN");
		return EXIT_FAILURE;
	}

	/* Bind address and socket together */
	ret = bind(listen_sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret == -1) {
		perror("bind()");
		close(listen_sock_fd);
		return EXIT_FAILURE;
	}

	/* Create listening queue (client requests) */
	ret = listen(listen_sock_fd, CLIENT_QUEUE_LEN);
	if (ret == -1) {
		perror("listen()");
		close(listen_sock_fd);
		return EXIT_FAILURE;
	}
	perror("Server listening");
	while (1) {
		/* Do TCP handshake with client */
		client_sock_fd = accept(listen_sock_fd,
				NULL,
				0);
		if (client_sock_fd == -1) {
			perror("accept()");
			close(listen_sock_fd);
			return EXIT_FAILURE;
		} else {
			perror("ACCEPT_SUCCESS");
		}

		char rb[1024];

		while (1) {
			ret = read(client_sock_fd, rb, 3);

			if (ret == -1) {
				perror("SERVVERread()");
				close(client_sock_fd);
				break;
			} else {
				fprintf(stderr, "received %c%c%c from client", rb[0], rb[1], rb[2]);
			}
			if (rb[0] == 'f' && rb[1] == 'f' && rb[2] == 'f') {
				close(client_sock_fd);
				break;
			}

		}
	}

	return EXIT_SUCCESS;
}
