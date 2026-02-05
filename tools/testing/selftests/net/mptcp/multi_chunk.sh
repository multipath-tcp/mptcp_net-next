#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(dirname "${0}")/mptcp_lib.sh"

cleanup()
{
	if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	fi

	mptcp_lib_ns_exit "${ns1}"
}

init()
{
	mptcp_lib_ns_init ns1

	local i
	for i in $(seq 1 4); do
		mptcp_lib_pm_nl_add_endpoint "${ns1}" "127.0.0.1" flags signal port 1000$i
	done

	mptcp_lib_pm_nl_set_limits "${ns1}" 8 8

	ip netns exec ${ns1} ip mptcp endpoint show
	ip netns exec ${ns1} ip mptcp limits
}

init
trap cleanup EXIT

ip netns exec $ns1 ./multi_chunk &

pid=$!
wait $pid
