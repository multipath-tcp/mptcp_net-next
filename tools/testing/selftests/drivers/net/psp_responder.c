// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <ynl.h>

#include "psp-user.h"

#define dbg(msg...)				\
do {						\
	if (opts->verbose)			\
		fprintf(stderr, "DEBUG: " msg);	\
} while (0)

static bool should_quit;

struct opts {
	int port;
	int ifindex;
	int devid;
	bool verbose;
};

enum accept_cfg {
	ACCEPT_CFG_NONE = 0,
	ACCEPT_CFG_CLEAR,
	ACCEPT_CFG_PSP,
};

static struct {
	unsigned char tx;
	unsigned char rx;
} psp_vers;

#define PSP_MAX_KEY_LEN		32

static int
rx_assoc(struct ynl_sock *ys, __u32 *spi, char *key, unsigned int *key_len,
	 int data_sock)
{
	struct psp_rx_assoc_rsp *rsp;
	struct psp_rx_assoc_req *req;

	req = psp_rx_assoc_req_alloc();

	psp_rx_assoc_req_set_sock_fd(req, data_sock);
	psp_rx_assoc_req_set_version(req, psp_vers.rx);

	rsp = psp_rx_assoc(ys, req);
	psp_rx_assoc_req_free(req);

	if (!rsp) {
		perror("ERROR: failed to Rx assoc");
		return -1;
	}

	*key_len = rsp->rx_key._len.key;
	memcpy(spi, &rsp->rx_key.spi, sizeof(*spi));
	memcpy(key, rsp->rx_key.key, *key_len);

	psp_rx_assoc_rsp_free(rsp);

	return 0;
}

static int
tx_assoc(struct ynl_sock *ys, __u8 version, __u32 spi, char *key,
	 unsigned int key_len, int data_sock)
{
	struct psp_tx_assoc_rsp *tsp;
	struct psp_tx_assoc_req *teq;

	teq = psp_tx_assoc_req_alloc();

	psp_tx_assoc_req_set_sock_fd(teq, data_sock);
	psp_tx_assoc_req_set_version(teq, version);
	psp_tx_assoc_req_set_tx_key_spi(teq, spi);
	psp_tx_assoc_req_set_tx_key_key(teq, key, key_len);

	tsp = psp_tx_assoc(ys, teq);
	psp_tx_assoc_req_free(teq);
	if (!tsp) {
		perror("ERROR: failed to Tx assoc");
		return -1;
	}
	psp_tx_assoc_rsp_free(tsp);

	return 0;
}

static int conn_setup_psp(struct ynl_sock *ys, struct opts *opts, int data_sock)
{
	char info[sizeof(__u32) + PSP_MAX_KEY_LEN];
	unsigned int key_len;
	ssize_t sz;
	__u32 spi;

	dbg("create PSP connection\n");

	if (rx_assoc(ys, &spi, &info[sizeof(spi)], &key_len, data_sock))
		return -1;

	// SPI exchange
	memcpy(info, &spi, sizeof(spi));
	sz = sizeof(spi) + key_len;

	send(data_sock, info, sz, MSG_WAITALL);

	sz = recv(data_sock, info, sz, MSG_WAITALL);
	if (sz < 0) {
		perror("ERROR: failed to read PSP key from sock");
		return -1;
	}
	memcpy(&spi, info, sizeof(spi));

	return tx_assoc(ys, psp_vers.tx, spi, &info[sizeof(spi)], key_len,
			data_sock);
}

static void send_ack(int sock)
{
	send(sock, "ack", 4, MSG_WAITALL);
}

static void send_err(int sock)
{
	send(sock, "err", 4, MSG_WAITALL);
}

static void send_str(int sock, int value)
{
	char buf[128];
	int ret;

	ret = snprintf(buf, sizeof(buf), "%d", value);
	send(sock, buf, ret + 1, MSG_WAITALL);
}

struct assoc_msg {
	__be32 spi;
	__u8 version;
	__u8 key_len;
	__u8 pad[2];
	char key[PSP_MAX_KEY_LEN];
};

static void
handle_rx_assoc(struct ynl_sock *ys, int data_sock, int comm_sock)
{
	struct assoc_msg msg = {};
	unsigned int key_len;
	__u32 spi;

	if (data_sock < 0) {
		fprintf(stderr, "WARN: rx assoc but no data sock\n");
		send_err(comm_sock);
		return;
	}

	if (rx_assoc(ys, &spi, msg.key, &key_len, data_sock)) {
		fprintf(stderr, "ERROR: rx_assoc() failed\n");
		send_err(comm_sock);
		return;
	}

	msg.spi = htonl(spi);
	msg.version = psp_vers.rx;
	msg.key_len = key_len;
	send_ack(comm_sock);
	send(comm_sock, &msg, sizeof(msg), MSG_WAITALL);
}

static void
handle_tx_assoc(struct ynl_sock *ys, char *data, int data_sock, int comm_sock)
{
	struct assoc_msg msg;

	if (data_sock < 0) {
		fprintf(stderr, "WARN: tx assoc but no data sock\n");
		send_err(comm_sock);
		return;
	}

	memcpy(&msg, data, sizeof(msg));
	if (msg.key_len > PSP_MAX_KEY_LEN) {
		fprintf(stderr, "ERROR: tx assoc key too long\n");
		send_err(comm_sock);
		return;
	}

	if (tx_assoc(ys, msg.version, ntohl(msg.spi), msg.key, msg.key_len,
		     data_sock)) {
		fprintf(stderr, "ERROR: tx_assoc() failed!\n");
		send_err(comm_sock);
		return;
	}

	send_ack(comm_sock);
}

static int rotate_key(struct ynl_sock *ys, int devid)
{
	struct psp_key_rotate_rsp *rsp;
	struct psp_key_rotate_req *req;

	req = psp_key_rotate_req_alloc();

	psp_key_rotate_req_set_id(req, devid);

	rsp = psp_key_rotate(ys, req);
	psp_key_rotate_req_free(req);

	if (!rsp) {
		perror("ERROR: failed to rotate key");
		return -1;
	}

	psp_key_rotate_rsp_free(rsp);

	return 0;
}

static void
handle_key_rotate(struct ynl_sock *ys, struct opts *opts, int comm_sock)
{
	if (opts->devid < 0) {
		fprintf(stderr, "WARN: key rotate but no PSP device\n");
		send_err(comm_sock);
		return;
	}

	if (rotate_key(ys, opts->devid)) {
		fprintf(stderr, "ERROR: rotate_key() failed\n");
		send_err(comm_sock);
		return;
	}

	send_ack(comm_sock);
}

static void
run_session(struct ynl_sock *ys, struct opts *opts,
	    int server_sock, int comm_sock)
{
	enum accept_cfg accept_cfg = ACCEPT_CFG_NONE;
	struct pollfd pfds[3];
	size_t data_read = 0;
	int data_sock = -1;

	while (true) {
		bool race_close = false;
		int nfds;

		memset(pfds, 0, sizeof(pfds));

		pfds[0].fd = server_sock;
		pfds[0].events = POLLIN;

		pfds[1].fd = comm_sock;
		pfds[1].events = POLLIN;

		nfds = 2;
		if (data_sock >= 0) {
			pfds[2].fd = data_sock;
			pfds[2].events = POLLIN;
			nfds++;
		}

		dbg(" ...\n");
		if (poll(pfds, nfds, -1) < 0) {
			perror("poll");
			break;
		}

		/* data sock */
		if (pfds[2].revents & POLLIN) {
			char buf[8192];
			ssize_t n;

			n = recv(data_sock, buf, sizeof(buf), 0);
			if (n <= 0) {
				if (n < 0)
					perror("data read");
				close(data_sock);
				data_sock = -1;
				dbg("data sock closed\n");
			} else {
				data_read += n;
				dbg("data read %zd\n", data_read);
			}
		}

		/* comm sock */
		if (pfds[1].revents & POLLIN) {
			static char buf[4096];
			static ssize_t off;
			bool consumed;
			ssize_t n;

			n = recv(comm_sock, &buf[off], sizeof(buf) - off, 0);
			if (n <= 0) {
				if (n < 0)
					perror("comm read");
				return;
			}

			off += n;
			n = off;

#define __consume(sz)						\
		({						\
			if (n == (sz)) {			\
				off = 0;			\
			} else {				\
				off -= (sz);			\
				memmove(buf, &buf[(sz)], off);	\
			}					\
		})

#define cmd(_name)							\
		({							\
			ssize_t sz = sizeof(_name);			\
			bool match = n >= sz &&	!memcmp(buf, _name, sz); \
									\
			if (match) {					\
				dbg("command: " _name "\n");		\
				__consume(sz);				\
			}						\
			consumed |= match;				\
			match;						\
		})

#define cmd_w_msg(_name, _type)						\
		(off >= sizeof(_name) + sizeof(_type) && cmd(_name))

			do {
				consumed = false;

				if (cmd("read len"))
					send_str(comm_sock, data_read);

				if (cmd("data echo")) {
					if (data_sock >= 0)
						send(data_sock, "echo", 5,
						     MSG_WAITALL);
					else
						fprintf(stderr, "WARN: echo but no data sock\n");
					send_ack(comm_sock);
				}
				if (cmd("rx assoc"))
					handle_rx_assoc(ys, data_sock,
							comm_sock);
				if (cmd_w_msg("tx assoc", struct assoc_msg)) {
					handle_tx_assoc(ys, buf, data_sock,
							comm_sock);
					__consume(sizeof(struct assoc_msg));
				}
				if (cmd("key rotate"))
					handle_key_rotate(ys, opts, comm_sock);
				if (cmd("data close")) {
					if (data_sock >= 0) {
						close(data_sock);
						data_sock = -1;
						send_ack(comm_sock);
					} else {
						race_close = true;
					}
				}
				if (cmd("conn psp")) {
					if (accept_cfg != ACCEPT_CFG_NONE)
						fprintf(stderr, "WARN: old conn config still set!\n");
					accept_cfg = ACCEPT_CFG_PSP;
					send_ack(comm_sock);
					/* next two bytes are versions */
					if (off >= 2) {
						memcpy(&psp_vers, buf, 2);
						__consume(2);
					} else {
						fprintf(stderr, "WARN: short conn psp command!\n");
					}
				}
				if (cmd("conn clr")) {
					if (accept_cfg != ACCEPT_CFG_NONE)
						fprintf(stderr, "WARN: old conn config still set!\n");
					accept_cfg = ACCEPT_CFG_CLEAR;
					send_ack(comm_sock);
				}
				if (cmd("exit"))
					should_quit = true;
#undef cmd_w_msg
#undef cmd

				if (!consumed) {
					fprintf(stderr, "WARN: unknown cmd: [%zd] %s\n",
						off, buf);
				}
			} while (consumed && off);
		}

		/* server sock */
		if (pfds[0].revents & POLLIN) {
			if (data_sock >= 0) {
				fprintf(stderr, "WARN: new data sock but old one still here\n");
				close(data_sock);
				data_sock = -1;
			}
			data_sock = accept(server_sock, NULL, NULL);
			if (data_sock < 0) {
				perror("accept");
				continue;
			}
			data_read = 0;

			if (accept_cfg == ACCEPT_CFG_CLEAR) {
				dbg("new data sock: clear\n");
				/* nothing to do */
			} else if (accept_cfg == ACCEPT_CFG_PSP) {
				dbg("new data sock: psp\n");
				conn_setup_psp(ys, opts, data_sock);
			} else {
				fprintf(stderr, "WARN: new data sock but no config\n");
			}
			accept_cfg = ACCEPT_CFG_NONE;
		}

		if (race_close) {
			if (data_sock >= 0) {
				/* indeed, ordering problem, handle the close */
				close(data_sock);
				data_sock = -1;
				send_ack(comm_sock);
			} else {
				fprintf(stderr, "WARN: close but no data sock\n");
				send_err(comm_sock);
			}
		}
	}
	dbg("session ending\n");
}

static int spawn_server(struct opts *opts)
{
	struct sockaddr_in6 addr;
	int fd;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("can't open socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));

	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(opts->port);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		perror("can't bind socket");
		return -1;
	}

	if (listen(fd, 5)) {
		perror("can't listen");
		return -1;
	}

	return fd;
}

static int run_responder(struct ynl_sock *ys, struct opts *opts)
{
	int server_sock, comm;

	server_sock = spawn_server(opts);
	if (server_sock < 0)
		return 4;

	while (!should_quit) {
		comm = accept(server_sock, NULL, NULL);
		if (comm < 0) {
			perror("accept failed");
		} else {
			run_session(ys, opts, server_sock, comm);
			close(comm);
		}
	}

	return 0;
}

static void usage(const char *name, const char *miss)
{
	if (miss)
		fprintf(stderr, "Missing argument: %s\n", miss);

	fprintf(stderr, "Usage: %s -p port [-v] [-i ifindex]\n", name);
	exit(EXIT_FAILURE);
}

static void parse_cmd_opts(int argc, char **argv, struct opts *opts)
{
	int opt;

	while ((opt = getopt(argc, argv, "vp:i:")) != -1) {
		switch (opt) {
		case 'v':
			opts->verbose = 1;
			break;
		case 'p':
			opts->port = atoi(optarg);
			break;
		case 'i':
			opts->ifindex = atoi(optarg);
			break;
		default:
			usage(argv[0], NULL);
		}
	}
}

static int psp_dev_set_ena(struct ynl_sock *ys, __u32 dev_id, __u32 versions)
{
	struct psp_dev_set_req *sreq;
	struct psp_dev_set_rsp *srsp;

	fprintf(stderr, "Set PSP enable on device %d to 0x%x\n",
		dev_id, versions);

	sreq = psp_dev_set_req_alloc();

	psp_dev_set_req_set_id(sreq, dev_id);
	psp_dev_set_req_set_psp_versions_ena(sreq, versions);

	srsp = psp_dev_set(ys, sreq);
	psp_dev_set_req_free(sreq);
	if (!srsp)
		return 10;

	psp_dev_set_rsp_free(srsp);
	return 0;
}

int main(int argc, char **argv)
{
	struct psp_dev_get_list *dev_list;
	__u32 ver_ena, ver_cap;
	struct opts opts = {};
	struct ynl_error yerr;
	struct ynl_sock *ys;
	int devid = -1;
	int ret;

	parse_cmd_opts(argc, argv, &opts);
	if (!opts.port)
		usage(argv[0], "port"); // exits

	ys = ynl_sock_create(&ynl_psp_family, &yerr);
	if (!ys) {
		fprintf(stderr, "YNL: %s\n", yerr.msg);
		return 1;
	}

	dev_list = psp_dev_get_dump(ys);
	if (ynl_dump_empty(dev_list) && ys->err.code)
		goto err_close;

	ynl_dump_foreach(dev_list, d) {
		if (opts.ifindex) {
			if (d->ifindex != opts.ifindex)
				continue;
			devid = d->id;
			ver_ena = d->psp_versions_ena;
			ver_cap = d->psp_versions_cap;
			break;
		} else if (devid < 0) {
			devid = d->id;
			ver_ena = d->psp_versions_ena;
			ver_cap = d->psp_versions_cap;
		} else {
			fprintf(stderr, "Multiple PSP devices found\n");
			goto err_close_silent;
		}
	}
	psp_dev_get_list_free(dev_list);
	opts.devid = devid;

	if (opts.ifindex && devid < 0)
		fprintf(stderr,
			"WARN: PSP device with ifindex %d requested on cmdline, not found\n",
			opts.ifindex);

	if (devid >= 0 && ver_ena != ver_cap) {
		ret = psp_dev_set_ena(ys, devid, ver_cap);
		if (ret)
			goto err_close;
	}

	ret = run_responder(ys, &opts);

	if (devid >= 0 && ver_ena != ver_cap &&
	    psp_dev_set_ena(ys, devid, ver_ena))
		fprintf(stderr, "WARN: failed to set the PSP versions back\n");

	ynl_sock_destroy(ys);

	return ret;

err_close:
	fprintf(stderr, "YNL: %s\n", ys->err.msg);
err_close_silent:
	ynl_sock_destroy(ys);
	return 2;
}
