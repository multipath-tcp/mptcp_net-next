#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Regression test for stale ADD_ADDR anno_list entry on id 0 removal

. "$(dirname "${0}")/mptcp_lib.sh"

ret=0
ns1=""
ns2=""
err=$(mktemp)
timeout_poll=30
port=50000

cleanup()
{
	rm -f "${err}"
	mptcp_lib_ns_exit "${ns1}" "${ns2}"
}

mptcp_lib_check_mptcp
mptcp_lib_check_tools ip

trap cleanup EXIT

mptcp_lib_ns_init ns1 ns2

ip link add ns1eth1 netns "${ns1}" type veth peer name ns2eth1 netns "${ns2}"
ip -net "${ns1}" link set lo up
ip -net "${ns2}" link set lo up
ip -net "${ns1}" link set ns1eth1 up
ip -net "${ns2}" link set ns2eth1 up
ip -net "${ns1}" addr add 10.0.1.1/24 dev ns1eth1
ip -net "${ns1}" addr add 10.0.2.1/24 dev ns1eth1
ip -net "${ns1}" addr add 10.0.3.1/24 dev ns1eth1
ip -net "${ns2}" addr add 10.0.1.2/24 dev ns2eth1
ip -net "${ns2}" addr add 10.0.2.2/24 dev ns2eth1
ip -net "${ns2}" addr add 10.0.3.2/24 dev ns2eth1

mptcp_lib_pm_nl_set_limits "${ns1}" 8 8
mptcp_lib_pm_nl_set_limits "${ns2}" 8 8

ip netns exec "${ns1}" ./mptcp_connect -t "${timeout_poll}" -l -p "${port}" \
	0.0.0.0 < /dev/zero > /dev/null 2>"${err}" &
spid=$!
mptcp_lib_wait_local_port_listen "${ns1}" "${port}"
ip netns exec "${ns2}" ./mptcp_connect -t "${timeout_poll}" -p "${port}" \
	10.0.1.1 < /dev/zero > /dev/null 2>"${err}" &
cpid=$!

sleep 2

warn_before=$(dmesg | grep -c "WARNING: net/mptcp/pm")

# 1. signal 10.0.2.1: peer joins, second subflow keeps connection alive
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.2.1 flags signal
sleep 2

# 2. signal MPC address 10.0.1.1: anno_list entry created for id 0
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.1 flags signal
sleep 1

# 3. remove id 0: stale entry survives on unfixed kernels
mptcp_lib_pm_nl_del_endpoint "${ns1}" 0 10.0.1.1
sleep 1

# 4. force PM reselection: hits stale entry on unfixed kernels
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.3.1 flags signal
sleep 2

warn_after=$(dmesg | grep -c "WARNING: net/mptcp/pm")

kill "${cpid}" "${spid}" 2>/dev/null
wait "${cpid}" 2>/dev/null
wait "${spid}" 2>/dev/null

if [ "${warn_after}" -gt "${warn_before}" ]; then
	mptcp_lib_result_fail "stale ADD_ADDR warning triggered on id 0 removal"
	ret=1
else
	mptcp_lib_result_pass "no stale ADD_ADDR warning on id 0 removal"
fi

mptcp_lib_result_print_all_tap

exit ${ret}
