#!/bin/bash
#This is an example of environmen that was used to generate wireshark
sudo ip netns add server
sudo ip netns add client
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns server
sudo ip link set veth0 netns client
sudo ip netns exec client ip a a 10.10.0.1/24 dev veth0
sudo ip netns exec server ip a a 10.10.0.2/24 dev veth1
sudo ip netns exec client ip link set dev  veth0 up
sudo ip netns exec server ip link set dev  veth1 up
sudo ip netns exec server bash -c "echo 2 > /proc/sys/net/ipv4/tcp_fastopen"
sudo ip netns exec client bash -c "echo 1 > /proc/sys/net/ipv4/tcp_fastopen"
