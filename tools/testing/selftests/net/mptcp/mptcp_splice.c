// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025, Kylin Software */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

#define BUFFER_SIZE 65536

char *server_ip;
int port;

static int server(char *output)
{
	int server_fd, client_fd, out_fd;
	struct sockaddr_in address;
	int addrlen = sizeof(address);
	int pipefd[2];
	ssize_t bytes;
	int opt = 1;

	server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (server_fd < 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
		       &opt, sizeof(opt))) {
		perror("setsockopt");
		goto close_server;
	}

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port);

	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		perror("bind failed");
		goto close_server;
	}

	if (listen(server_fd, 3) < 0) {
		perror("listen");
		goto close_server;
	}

	printf("Server listening on port %d...\n", port);

	client_fd = accept(server_fd, (struct sockaddr *)&address,
			   (socklen_t *)&addrlen);
	if (client_fd < 0) {
		perror("accept");
		goto close_client;
	}

	printf("Client connected. Receiving file...\n");

	if (pipe(pipefd)) {
		perror("pipe");
		goto close_client;
	}

	out_fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out_fd < 0) {
		perror("open");
		goto close_pipe;
	}

	while ((bytes = splice(client_fd, NULL, pipefd[1], NULL, BUFFER_SIZE,
			       SPLICE_F_MOVE | SPLICE_F_MORE)) > 0) {
		splice(pipefd[0], NULL, out_fd, NULL, bytes, SPLICE_F_MOVE | SPLICE_F_MORE);
	}

	if (bytes == -1) {
		perror("splice");
		goto close_fd;
	}

	printf("File transfer completed. Received %ld bytes.\n",
	       lseek(out_fd, 0, SEEK_CUR));

close_fd:
	close(out_fd);
close_pipe:
	close(pipefd[0]);
	close(pipefd[1]);
close_client:
	close(client_fd);
close_server:
	close(server_fd);

	return 0;
}

static int client(char *input)
{
	struct sockaddr_in serv_addr;
	int sock_fd, in_fd;
	int pipefd[2];
	ssize_t bytes;

	sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (sock_fd < 0) {
		perror("Socket creation error");
		exit(EXIT_FAILURE);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
		perror("Invalid address/ Address not supported");
		goto close_sock;
	}

	if (connect(sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("Connection Failed");
		goto close_sock;
	}

	printf("Connected to server. Sending file...\n");

	if (pipe(pipefd)) {
		perror("pipe");
		goto close_sock;
	}

	in_fd = open(input, O_RDONLY);
	if (in_fd == -1) {
		perror("open");
		goto close_pipe;
	}

	while ((bytes = splice(in_fd, NULL, pipefd[1], NULL, BUFFER_SIZE,
			       SPLICE_F_MOVE | SPLICE_F_MORE)) > 0) {
		splice(pipefd[0], NULL, sock_fd, NULL, bytes, SPLICE_F_MOVE | SPLICE_F_MORE);
	}

	if (bytes == -1) {
		perror("splice");
		goto close_fd;
	}

	printf("File transfer completed. Sent %ld bytes.\n",
	       lseek(in_fd, 0, SEEK_CUR));

close_fd:
	close(in_fd);
close_pipe:
	close(pipefd[0]);
	close(pipefd[1]);
close_sock:
	shutdown(sock_fd, SHUT_WR);
	close(sock_fd);

	return 0;
}

static void die_usage(void)
{
	fprintf(stderr, "Usage: mptcp_splice -l -p <port> -o <output_file>\n");
	fprintf(stderr, "       mptcp_splice -a <addr> -p <port> -i <input_file>\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	char *input = "", *output = "";
	bool listen_mode = false;
	int c;

	if (argc < 2)
		die_usage();

	while ((c = getopt(argc, argv, "hli:o:a:p:")) != -1) {
		switch (c) {
		case 'h':
			die_usage();
			break;
		case 'l':
			listen_mode = true;
			break;
		case 'i':
			input = optarg;
			break;
		case 'o':
			output = optarg;
			break;
		case 'a':
			server_ip = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		default:
			die_usage();
			break;
		}
	}

	if (listen_mode)
		return server(output);
	return client(input);
}
