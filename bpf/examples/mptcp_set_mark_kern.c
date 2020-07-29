#include <asm/socket.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define DEBUG 1

char _license[] SEC("license") = "GPL";

struct key_t {
	__u32 ip4;
	__u16 port;
};

struct bpf_map_def SEC("maps") mptcp_sf = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct key_t),
	.value_size = sizeof(__u32),
	.max_entries = 100
};

#ifdef DEBUG
char fmt1[] = "Key : %x %x\n";
char fmt2[] = "Failed to get bpf_sock\n";
char fmt3[] = "Failed to get bpf_tcp_sock\n";
char fmt4[] = "Failed to update the socket mark\n";
#endif

SEC("sockops")
int mark_mptcp_sf(struct bpf_sock_ops *skops)
{

	int ret = 1;

	if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
		return ret;

	struct bpf_sock *sk = skops->sk;
	if (!sk) {
#ifdef DEBUG
		bpf_trace_printk(fmt2, sizeof(fmt2));
#endif
		return ret;
	}

	struct bpf_tcp_sock *tsk = bpf_tcp_sock(sk);
	if (!tsk) {
#ifdef DEBUG
		bpf_trace_printk(fmt3, sizeof(fmt3));
#endif
		return ret;
	}

	if (tsk->is_mptcp) {
		struct key_t key = {};
		key.ip4 = sk->dst_ip4;
		key.port = sk->dst_port;
#ifdef DEBUG
		bpf_trace_printk(fmt1, sizeof(fmt1), key.ip4, key.port);
#endif

		__u32 init = 1, mark, *val = bpf_map_lookup_elem(&mptcp_sf, &key);
		if (val) {
			__sync_fetch_and_add(val, 1);
			mark = *val;
		} else {
			bpf_map_update_elem(&mptcp_sf, &key, &init, BPF_ANY);
			mark = init;
		}

		if (bpf_setsockopt(skops, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
#ifdef DEBUG
			bpf_trace_printk(fmt4, sizeof(fmt4));
#endif
	}

	return ret;
}
