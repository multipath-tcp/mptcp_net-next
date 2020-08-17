# eBPF example programs

This directory contains some examples of possible applications of eBPF programs on the MPTCP protocol.


## Prerequisite
- The [`use_mptcp`](ihttps://github.com/pabeni/mptcp-tools) tool is required in the current folder in order to run the examples.
- The [`mptcp_net-next`](https://github.com/multipath-tcp/mptcp_net-next) kernel is supposed to be accessible at `${PWD}/../../../mptcp_net-next`.
- Nftables>=v0.9.2 and python3 are required.

## How to use

It is required that the examples have been compiled, see the [Makefile](Makefile).

### `mptcp_set_sf_sockopt_*`

This example shows how it is possible to :
- Identify the parent msk of an MPTCP subflow.
- Put different `sockopt` for each subflow of a same MPTCP connection.

Here especially, we implemented two different behaviours :
- A socket mark (`SOL_SOCKET` `SO_MARK`) is put on each subflow of a same MPTCP connection. The order of creation of the current subflow defines its mark.
- The TCP CC algorithm of the very first subflow of an MPTCP connection is set to `vegas`.

A bash script is provided to run this example : `./mptcp_set_sf_sockopt_test.sh | less`. As it is quite verbose, it is recommended to pipe its output in `less`.

Here are the expected output informations :
- During the exchange between the client and the server, `ss` process are launched at regular interval on both sides to observe the evolution of the `sockopt`.
> Currently this part is not fully functional.
>
> It is required to slow down the connection by applying some delay (>100ms) on the server-side interfaces in order to use `ss`.
> But when delay (>50ms) is applied, the client-side sends reset on subflows creation.

- Once the data exchange between the client and the server ended, the script will output :
	- The client-side `tcpdump` trace of the connection
	- The client-side output filter
	- The client-side BPF debug trace

Here is a sample of the expected output :

```

[...]

[INFO] Client-side tcpdump log :
14:02:25.150756 IP 10.0.1.1.54116 > 10.0.1.2.8000: Flags [S], seq 655299911, win 64240, options [mss 1460,sackOK,TS val 4288420401 ecr 0,nop,wscale 7,mptcp capable[bad opt]>
14:02:25.150838 IP 10.0.1.2.8000 > 10.0.1.1.54116: Flags [S.], seq 384090692, ack 655299912, win 65160, options [mss 1460,sackOK,TS val 4049039081 ecr 4288420401,nop,wscale 7,mptcp capable Unknown Version (1)], length 0
14:02:25.150893 IP 10.0.1.1.54116 > 10.0.1.2.8000: Flags [.], ack 1, win 502, options [nop,nop,TS val 4288420401 ecr 4049039081,mptcp capable Unknown Version (1)], length 0
14:02:25.164565 IP 10.0.1.1.54116 > 10.0.1.2.8000: Flags [P.], seq 1:78, ack 1, win 502, options [nop,nop,TS val 4288420415 ecr 4049039081,mptcp capable[bad opt]>
14:02:25.164582 IP 10.0.1.2.8000 > 10.0.1.1.54116: Flags [.], ack 78, win 509, options [nop,nop,TS val 4049039095 ecr 4288420415,mptcp dss ack 10687113225447666601], length 0
14:02:25.165031 IP 10.0.2.1.51985 > 10.0.1.2.8000: Flags [S], seq 3827805215, win 64240, options [mss 1460,sackOK,TS val 2921201885 ecr 0,nop,wscale 7,mptcp join backup id 1 token 0x153035fd nonce 0xde013ea7], length 0
14:02:25.165061 IP 10.0.1.2.8000 > 10.0.2.1.51985: Flags [S.], seq 4233574390, ack 3827805216, win 65160, options [mss 1460,sackOK,TS val 729822840 ecr 2921201885,nop,wscale 7,mptcp join backup
id 0 hmac 0x994d937f81fb1a76 nonce 0xcaa06001], length 0
14:02:25.165087 IP 10.0.2.1.51985 > 10.0.1.2.8000: Flags [.], ack 1, win 502, options [nop,nop,TS val 2921201885 ecr 729822840,mptcp join hmac 0x40db49cb3557778c7721e23a675d59687a41090e], length 0
14:02:25.165107 IP 10.0.1.2.8000 > 10.0.2.1.51985: Flags [.], ack 1, win 510, options [nop,nop,TS val 729822840 ecr 2921201885,mptcp dss ack 355464105], length 0
14:02:25.165128 IP 10.0.3.1.60041 > 10.0.1.2.8000: Flags [S], seq 2982449334, win 64240, options [mss 1460,sackOK,TS val 4266969079 ecr 0,nop,wscale 7,mptcp join backup id 2 token 0x153035fd nonce 0x1f382df], length 0
14:02:25.165150 IP 10.0.1.2.8000 > 10.0.3.1.60041: Flags [S.], seq 3431902562, ack 2982449335, win 65160, options [mss 1460,sackOK,TS val 3815681013 ecr 4266969079,nop,wscale 7,mptcp join backup id 0 hmac 0x6fb7c4ebd45363f nonce 0x4f412e69], length 0
14:02:25.165162 IP 10.0.3.1.60041 > 10.0.1.2.8000: Flags [.], ack 1, win 502, options [nop,nop,TS val 4266969080 ecr 3815681013,mptcp join hmac 0x63dadd4a5446f6d6e0633cc43549ce5c1c5ad545], length 0

[...]

[INFO] Client-side output filters :
table inet filter {
        chain output {
                type filter hook output priority filter; policy accept;
                tcp dport 8000 socket mark 0x00000005 counter packets 0 bytes 0
                tcp dport 8000 socket mark 0x00000004 counter packets 0 bytes 0
                tcp dport 8000 socket mark 0x00000003 counter packets 6 bytes 412
                tcp dport 8000 socket mark 0x00000002 counter packets 6 bytes 412
                tcp dport 8000 socket mark 0x00000001 counter packets 9 bytes 693
                tcp dport 8000 socket mark 0x00000000 counter packets 0 bytes 0
        }
}

[INFO] Client-side bpf trace :
# tracer: nop
#
# entries-in-buffer/entries-written: 3/3   #P:1
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
            curl-11297 [000] d... 18011.270069: bpf_trace_printk: Mark <1> : return code <0>

     kworker/0:2-26775 [000] d... 18011.271071: bpf_trace_printk: Mark <2> : return code <0>

     kworker/0:2-26775 [000] d... 18011.271142: bpf_trace_printk: Mark <3> : return code <0>
```
