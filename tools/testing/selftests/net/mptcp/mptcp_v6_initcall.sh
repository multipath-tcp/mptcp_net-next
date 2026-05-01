#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Verify that MPTCP IPv6 subflow child sockets are allocated from the
# TCPv6 slab cache.
#
# tcpv6_prot_override is initialised by copying tcpv6_prot, which is only
# safe after proto_register(&tcpv6_prot) has populated tcpv6_prot.slab.
# If the override copy runs too early during init, override.slab stays
# NULL and __ro_after_init freezes that. Subflow child sockets then fall
# back to kmalloc (kmalloc-4k for a TCPv6 sock), which lacks
# SLAB_TYPESAFE_BY_RCU; lockless ehash lookups in __inet_lookup_established
# can read freed memory.
#
# This test exercises the IPv6 accept path, which goes through the
# override proto, and then asserts that the live TCPv6 slab population
# grew. On a kernel where the override slab is NULL the delta is ~0,
# because the children land in kmalloc-4k instead.

#shellcheck disable=SC2086

. "$(dirname "${0}")/mptcp_lib.sh"

ns1=""
ns2=""
ret=0

NR_CONNS=20
TIMEOUT_POLL=30
TIMEOUT_TEST=$((TIMEOUT_POLL * 2 + 1))
PORT_BASE=20000

# This function is used in the cleanup trap
#shellcheck disable=SC2317,SC2329
cleanup()
{
	for ns in "${ns1}" "${ns2}"; do
		[ -n "${ns}" ] || continue
		ip netns pids "${ns}" | xargs --no-run-if-empty kill -SIGKILL &>/dev/null
	done
	mptcp_lib_ns_exit "${ns1}" "${ns2}"
}

mptcp_lib_check_mptcp
mptcp_lib_check_tools ip ss

if ! mptcp_lib_kallsyms_has "tcpv6_prot_override$"; then
	mptcp_lib_pr_skip "CONFIG_MPTCP_IPV6 not available"
	exit ${KSFT_SKIP}
fi

if ! [ -r /proc/slabinfo ]; then
	mptcp_lib_pr_skip "/proc/slabinfo not readable"
	exit ${KSFT_SKIP}
fi

if ! awk '/^TCPv6 / { found = 1 } END { exit !found }' /proc/slabinfo; then
	mptcp_lib_pr_skip "TCPv6 slab cache not present"
	exit ${KSFT_SKIP}
fi

trap cleanup EXIT
mptcp_lib_ns_init ns1 ns2

ip -n "${ns1}" link add eth1 type veth peer name eth1 netns "${ns2}"
ip -n "${ns1}" link set eth1 up
ip -n "${ns1}" -6 addr add fc00::1/64 dev eth1 nodad
ip -n "${ns2}" link set eth1 up
ip -n "${ns2}" -6 addr add fc00::2/64 dev eth1 nodad

# Wait for DAD-less addresses to settle
ip -n "${ns1}" -6 route get fc00::2 >/dev/null 2>&1 || sleep 0.1

get_tcpv6_active()
{
	awk '/^TCPv6 / { print $2 }' /proc/slabinfo
}

before=$(get_tcpv6_active)

for i in $(seq 1 ${NR_CONNS}); do
	echo "a" |
		timeout ${TIMEOUT_TEST} \
			ip netns exec "${ns2}" \
				./mptcp_connect -6 -p $((PORT_BASE + i)) -l \
					-t ${TIMEOUT_POLL} -w ${TIMEOUT_POLL} \
					:: >/dev/null 2>&1 &
done

# wait_local_port_listen() only checks one port. Walk every port so we
# do not start the connectors before all listeners are ready.
for i in $(seq 1 ${NR_CONNS}); do
	mptcp_lib_wait_local_port_listen "${ns2}" $((PORT_BASE + i))
done

for i in $(seq 1 ${NR_CONNS}); do
	echo "b" |
		timeout ${TIMEOUT_TEST} \
			ip netns exec "${ns1}" \
				./mptcp_connect -6 -p $((PORT_BASE + i)) \
					-t ${TIMEOUT_POLL} -w ${TIMEOUT_POLL} \
					fc00::2 >/dev/null 2>&1 &
done

# Wait for the accept side to materialise child sockets. ss reports the
# number of established TCP connections in ns2 owned by mptcp_connect.
established=0
for _ in $(seq 20); do
	established=$(ip netns exec "${ns2}" ss -H -t -6 state established 2>/dev/null | wc -l)
	[ "${established}" -ge "${NR_CONNS}" ] && break
	sleep 1
done

after=$(get_tcpv6_active)
delta=$(( after - before ))

# Conservative threshold: NR_CONNS connections (each producing at least
# a server-side accepted child) must leave a clearly observable footprint
# in the TCPv6 slab. On a regressed kernel, override.slab == NULL routes
# every child into kmalloc-4k and the TCPv6 delta stays near zero.
threshold=$(( NR_CONNS / 2 ))

msg="TCPv6 slab gains MPTCPv6 subflow children"
mptcp_lib_print_title "${msg}"
if [ "${established}" -lt "${NR_CONNS}" ]; then
	mptcp_lib_pr_fail "only ${established}/${NR_CONNS} connections established"
	mptcp_lib_result_fail "${msg}"
	ret=${KSFT_FAIL}
elif [ "${delta}" -ge "${threshold}" ]; then
	mptcp_lib_pr_ok "delta=${delta}"
	mptcp_lib_result_pass "${msg}"
else
	mptcp_lib_pr_fail "delta=${delta} below ${threshold}:" \
		"subflow children likely in kmalloc fallback"
	mptcp_lib_result_fail "${msg}"
	ret=${KSFT_FAIL}
fi

mptcp_lib_result_print_all_tap
exit ${ret}
