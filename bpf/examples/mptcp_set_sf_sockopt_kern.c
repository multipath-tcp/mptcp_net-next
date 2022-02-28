#include <asm/socket.h> 	// SOL_SOCKET, SO_MARK, ...
#include <linux/tcp.h> 	// TCP_CONGESTION
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#ifndef SOL_TCP
#define SOL_TCP 6
#endif

#ifndef TCP_CA_NAME_MAX
#define TCP_CA_NAME_MAX 16
#endif

char cc [TCP_CA_NAME_MAX] = "vegas";

/* Associate a subflow counter to each token */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 100);
} mptcp_sf SEC(".maps");

#define DEBUG 1

#ifdef DEBUG
char fmt1[] = "Mark <%u> : return code <%i>\n";
char fmt2[] = "Failed to get bpf_sock\n";
char fmt3[] = "Failed to get bpf_mptcp_sock\n";
char fmt4[] = "Failed to update sockopt\n";

#define pr_debug(msg, ...) bpf_trace_printk(msg, sizeof(msg), ##__VA_ARGS__);

#else

#define pr_debug(msg, ...)

#endif

SEC("sockops")
int mark_mptcp_sf(struct bpf_sock_ops *skops)
{
	__u32 init = 1, key, mark, *cnt;
	int err;

	if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
		goto out;

	struct bpf_sock *sk = skops->sk;
	if (!sk) {
		pr_debug(fmt2);
		goto out;
	}

	struct bpf_mptcp_sock *msk = bpf_mptcp_sock(sk);
	if (!msk) {
		pr_debug(fmt3);
		goto out;
	}

	key = msk->token;
	cnt = bpf_map_lookup_elem(&mptcp_sf, &key);

	if (cnt) {
		/* A new subflow is added to an existing MPTCP connection */
		__sync_fetch_and_add(cnt, 1);
		mark = *cnt;
	} else {
		/* A new MPTCP connection is just initiated and this is its primary
		 *  subflow
		 */
		bpf_map_update_elem(&mptcp_sf, &key, &init, BPF_ANY);
		mark = init;
	}

	/* Set the mark of the subflow's socket to its apparition order */
	err = bpf_setsockopt(skops, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	pr_debug(fmt1, mark, err);

	if (mark == 1)
		err = err ?: bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, cc,
					    TCP_CA_NAME_MAX);

	if (err < 0)
		pr_debug(fmt4);

out:
	return 0;
}
