#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test IPv6 force_forwarding interface property
#
# This test verifies that the force_forwarding property works correctly:
# - When global forwarding is disabled, packets are not forwarded normally
# - When force_forwarding is enabled on an interface, packets are forwarded
#   regardless of the global forwarding setting

source lib.sh

cleanup() {
    cleanup_ns $ns1 $ns2 $ns3
}

trap cleanup EXIT

setup_test() {
    # Create three namespaces: sender, router, receiver
    setup_ns ns1 ns2 ns3

    # Create veth pairs: ns1 <-> ns2 <-> ns3
    ip link add name veth12 type veth peer name veth21
    ip link add name veth23 type veth peer name veth32

    # Move interfaces to namespaces
    ip link set veth12 netns $ns1
    ip link set veth21 netns $ns2
    ip link set veth23 netns $ns2
    ip link set veth32 netns $ns3

    # Configure interfaces
    ip -n $ns1 addr add 2001:db8:1::1/64 dev veth12 nodad
    ip -n $ns2 addr add 2001:db8:1::2/64 dev veth21 nodad
    ip -n $ns2 addr add 2001:db8:2::1/64 dev veth23 nodad
    ip -n $ns3 addr add 2001:db8:2::2/64 dev veth32 nodad

    # Bring up interfaces
    ip -n $ns1 link set veth12 up
    ip -n $ns2 link set veth21 up
    ip -n $ns2 link set veth23 up
    ip -n $ns3 link set veth32 up

    # Add routes
    ip -n $ns1 route add 2001:db8:2::/64 via 2001:db8:1::2
    ip -n $ns3 route add 2001:db8:1::/64 via 2001:db8:2::1

    # Disable global forwarding
    ip netns exec $ns2 sysctl -qw net.ipv6.conf.all.forwarding=0
}

test_force_forwarding() {
    local ret=0

    echo "TEST: force_forwarding functionality"

    # Check if force_forwarding sysctl exists
    if ! ip netns exec $ns2 test -f /proc/sys/net/ipv6/conf/veth21/force_forwarding; then
        echo "SKIP: force_forwarding not available"
        return $ksft_skip
    fi

    # Test 1: Without force_forwarding, ping should fail
    ip netns exec $ns2 sysctl -qw net.ipv6.conf.veth21.force_forwarding=0
    ip netns exec $ns2 sysctl -qw net.ipv6.conf.veth23.force_forwarding=0

    if ip netns exec $ns1 ping -6 -c 1 -W 2 2001:db8:2::2 &>/dev/null; then
        echo "FAIL: ping succeeded when forwarding disabled"
        ret=1
    else
        echo "PASS: forwarding disabled correctly"
    fi

    # Test 2: With force_forwarding enabled, ping should succeed
    ip netns exec $ns2 sysctl -qw net.ipv6.conf.veth21.force_forwarding=1
    ip netns exec $ns2 sysctl -qw net.ipv6.conf.veth23.force_forwarding=1

    if ip netns exec $ns1 ping -6 -c 1 -W 2 2001:db8:2::2 &>/dev/null; then
        echo "PASS: force_forwarding enabled forwarding"
    else
        echo "FAIL: ping failed with force_forwarding enabled"
        ret=1
    fi

    return $ret
}

check_force_forwarding() {
    local dev=$1
    local expected=$2
    local msg=$3
    local val

    val=$(ip netns exec $ns2 sysctl -n net.ipv6.conf.$dev.force_forwarding) || return 1
    if [ "$val" = "$expected" ]; then
        echo "PASS: $msg"
        return 0
    fi

    echo "FAIL: $msg (got $val, expected $expected)"
    return 1
}

test_all_force_forwarding() {
    local ret=0

    echo "TEST: all.force_forwarding"

    ip netns exec $ns2 sysctl -qw net.ipv6.conf.veth21.force_forwarding=0 || return 1
    ip netns exec $ns2 sysctl -qw net.ipv6.conf.all.force_forwarding=1 || return 1
    check_force_forwarding veth21 1 "all.force_forwarding applied to interfaces" || ret=1

    # Rewriting the same value to all re-applies it to every interface
    ip netns exec $ns2 sysctl -qw net.ipv6.conf.veth21.force_forwarding=0 || return 1
    check_force_forwarding veth21 0 "interface force_forwarding overridden" || return 1
    ip netns exec $ns2 sysctl -qw net.ipv6.conf.all.force_forwarding=1 || return 1
    check_force_forwarding veth21 1 "unchanged all.force_forwarding re-applied" || ret=1

    if ip netns exec $ns1 ping -6 -c 1 -W 2 2001:db8:2::2 &>/dev/null; then
        echo "PASS: forwarding after re-applying all.force_forwarding"
    else
        echo "FAIL: ping failed after re-applying all.force_forwarding"
        ret=1
    fi

    # Disabling all.forwarding resets force_forwarding, including on all
    ip netns exec $ns2 sysctl -qw net.ipv6.conf.all.forwarding=1 || return 1
    ip netns exec $ns2 sysctl -qw net.ipv6.conf.all.forwarding=0 || return 1
    check_force_forwarding all 0 "all.forwarding=0 resets all.force_forwarding" || ret=1
    check_force_forwarding veth21 0 "all.forwarding=0 resets interface force_forwarding" || ret=1

    return $ret
}

echo "IPv6 force_forwarding test"
echo "=========================="

setup_test
test_force_forwarding
ret=$?
if [ $ret -eq 0 ]; then
    test_all_force_forwarding
    ret=$?
fi

if [ $ret -eq 0 ]; then
    echo "OK"
    exit 0
elif [ $ret -eq $ksft_skip ]; then
    echo "SKIP"
    exit $ksft_skip
else
    echo "FAIL"
    exit 1
fi
