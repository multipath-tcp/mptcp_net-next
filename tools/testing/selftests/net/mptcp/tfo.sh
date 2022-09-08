#!/bin/bash

set -x

DO_CLEANUP="${DO_CLEANUP:-1}"
DO_MPTCPIZE="${DO_MPTCPIZE:-1}"

cleanup() {
	if [ "${DO_CLEANUP}" == "0" ]; then
		return
	fi

	pkill tcpdump
	pkill python

	ip netns delete client
	ip netns delete server
}

netns() {
	ns="$1"
	shift
	ip netns exec "$ns" "$@"
}


trap cleanup EXIT

ip netns add client
ip netns add server

netns client sysctl net.ipv4.tcp_fastopen=0x5
netns server sysctl net.ipv4.tcp_fastopen=0x602

netns client ip link add eth0 type veth peer eth0 netns server
netns client ip addr add 6.6.6.1/24 dev eth0
netns server ip addr add 6.6.6.6/24 dev eth0
netns client ip link set eth0 up
netns server ip link set eth0 up

netns client tcpdump -i eth0 -w ./client.pcap &
sleep 1

if [ "${DO_MPTCPIZE}" == "0" ]; then
	LD_PRELOAD=
else
	LD_PRELOAD="$PWD/mptcpize/libmptcpwrap.so"
fi

LD_PRELOAD=${LD_PRELOAD} netns server python3 -m http.server 666 &
sleep 3

LD_PRELOAD=${LD_PRELOAD} netns client curl --tcp-fastopen -o out.txt http://6.6.6.6:666/tfo.sh
sleep 3

