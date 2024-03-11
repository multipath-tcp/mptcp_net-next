#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# Double quotes to prevent globbing and word splitting is recommended in new
# code but we accept it, especially because there were too many before having
# address all other issues detected by shellcheck.
#shellcheck disable=SC2086

. "$(dirname "${0}")/mptcp_lib.sh"

ret=0

usage() {
	echo "Usage: $0 [ -h ]"
}

optstring=h
while getopts "$optstring" option;do
	case "$option" in
	"h")
		usage $0
		exit ${KSFT_PASS}
		;;
	"?")
		usage $0
		exit ${KSFT_FAIL}
		;;
	esac
done

ns1=""
err=$(mktemp)

# This function is used in the cleanup trap
#shellcheck disable=SC2317
cleanup()
{
	rm -f $err
	mptcp_lib_ns_exit "${ns1}"
}

mptcp_lib_check_mptcp
mptcp_lib_check_tools ip

trap cleanup EXIT

mptcp_lib_ns_init ns1

check()
{
	local cmd="$1"
	local expected="$2"
	local msg="$3"
	local rc=0

	mptcp_lib_print_title "$msg"
	mptcp_lib_check_output "${err}" "${cmd}" "${expected}" || rc=${?}
	if [ ${rc} -eq 2 ]; then
		mptcp_lib_result_fail "${msg} # error ${rc}"
		ret=${KSFT_FAIL}
	elif [ ${rc} -eq 0 ]; then
		mptcp_lib_print_ok "[ OK ]"
		mptcp_lib_result_pass "${msg}"
	elif [ ${rc} -eq 1 ]; then
		mptcp_lib_result_fail "${msg} # different output"
		ret=${KSFT_FAIL}
	fi
}

check "ip netns exec $ns1 ./pm_nl_ctl dump" "" "defaults addr list"

default_limits="$(ip netns exec $ns1 ./pm_nl_ctl limits)"
if mptcp_lib_expect_all_features; then
	limits=$'accept 0\nsubflows 2'
	check "ip netns exec $ns1 ./pm_nl_ctl limits" "${limits}" "defaults limits"
fi

ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.1
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.2 flags subflow dev lo
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.3 flags signal,backup
endpoint="id 1 flags  10.0.1.1"
check "ip netns exec $ns1 ./pm_nl_ctl get 1" "${endpoint}" "simple add/get addr"

dump="$(printf '%s\n' \
	"id 1 flags  10.0.1.1" \
	"id 2 flags subflow dev lo 10.0.1.2" \
	"id 3 flags signal,backup 10.0.1.3")"
check "ip netns exec $ns1 ./pm_nl_ctl dump" \
	"${dump}" "dump addrs"

ip netns exec $ns1 ./pm_nl_ctl del 2
dump=$'id 1 flags  10.0.1.1\nid 3 flags signal,backup 10.0.1.3'
check "ip netns exec $ns1 ./pm_nl_ctl get 2" "" "simple del addr"
check "ip netns exec $ns1 ./pm_nl_ctl dump" \
	"${dump}" "dump addrs after del"

ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.3 2>/dev/null
check "ip netns exec $ns1 ./pm_nl_ctl get 4" "" "duplicate addr"

ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.4 flags signal
endpoint="id 4 flags signal 10.0.1.4"
check "ip netns exec $ns1 ./pm_nl_ctl get 4" "${endpoint}" "id addr increment"

for i in $(seq 5 9); do
	ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.$i flags signal >/dev/null 2>&1
done
endpoint="id 9 flags signal 10.0.1.9"
check "ip netns exec $ns1 ./pm_nl_ctl get 9" "${endpoint}" "hard addr limit"
check "ip netns exec $ns1 ./pm_nl_ctl get 10" "" "above hard addr limit"

ip netns exec $ns1 ./pm_nl_ctl del 9
for i in $(seq 10 255); do
	ip netns exec $ns1 ./pm_nl_ctl add 10.0.0.9 id $i
	ip netns exec $ns1 ./pm_nl_ctl del $i
done
dump="$(printf '%s\n' \
	"id 1 flags  10.0.1.1" \
	"id 3 flags signal,backup 10.0.1.3" \
	"id 4 flags signal 10.0.1.4" \
	"id 5 flags signal 10.0.1.5" \
	"id 6 flags signal 10.0.1.6" \
	"id 7 flags signal 10.0.1.7" \
	"id 8 flags signal 10.0.1.8")"
check "ip netns exec $ns1 ./pm_nl_ctl dump" "${dump}" "id limit"

ip netns exec $ns1 ./pm_nl_ctl flush
check "ip netns exec $ns1 ./pm_nl_ctl dump" "" "flush addrs"

ip netns exec $ns1 ./pm_nl_ctl limits 9 1 2>/dev/null
check "ip netns exec $ns1 ./pm_nl_ctl limits" "$default_limits" "rcv addrs above hard limit"

ip netns exec $ns1 ./pm_nl_ctl limits 1 9 2>/dev/null
check "ip netns exec $ns1 ./pm_nl_ctl limits" "$default_limits" "subflows above hard limit"

ip netns exec $ns1 ./pm_nl_ctl limits 8 8
limits=$'accept 8\nsubflows 8'
check "ip netns exec $ns1 ./pm_nl_ctl limits" "${limits}" "set limits"

ip netns exec $ns1 ./pm_nl_ctl flush
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.1
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.2
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.3 id 100
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.4
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.5 id 254
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.6
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.7
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.8
dump="$(printf '%s\n' \
	"id 1 flags  10.0.1.1" \
	"id 2 flags  10.0.1.2" \
	"id 3 flags  10.0.1.7" \
	"id 4 flags  10.0.1.8" \
	"id 100 flags  10.0.1.3" \
	"id 101 flags  10.0.1.4" \
	"id 254 flags  10.0.1.5" \
	"id 255 flags  10.0.1.6")"
check "ip netns exec $ns1 ./pm_nl_ctl dump" "${dump}" "set ids"

ip netns exec $ns1 ./pm_nl_ctl flush
ip netns exec $ns1 ./pm_nl_ctl add 10.0.0.1
ip netns exec $ns1 ./pm_nl_ctl add 10.0.0.2 id 254
ip netns exec $ns1 ./pm_nl_ctl add 10.0.0.3
ip netns exec $ns1 ./pm_nl_ctl add 10.0.0.4
ip netns exec $ns1 ./pm_nl_ctl add 10.0.0.5 id 253
ip netns exec $ns1 ./pm_nl_ctl add 10.0.0.6
ip netns exec $ns1 ./pm_nl_ctl add 10.0.0.7
ip netns exec $ns1 ./pm_nl_ctl add 10.0.0.8
dump="$(printf '%s\n' \
	"id 1 flags  10.0.0.1" \
	"id 2 flags  10.0.0.4" \
	"id 3 flags  10.0.0.6" \
	"id 4 flags  10.0.0.7" \
	"id 5 flags  10.0.0.8" \
	"id 253 flags  10.0.0.5" \
	"id 254 flags  10.0.0.2" \
	"id 255 flags  10.0.0.3")"
check "ip netns exec $ns1 ./pm_nl_ctl dump" "${dump}" "wrap-around ids"

ip netns exec $ns1 ./pm_nl_ctl flush
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.1 flags subflow
ip netns exec $ns1 ./pm_nl_ctl set 10.0.1.1 flags backup
dump="id 1 flags subflow,backup 10.0.1.1"
check "ip netns exec $ns1 ./pm_nl_ctl dump" "${dump}" "set flags (backup)"
ip netns exec $ns1 ./pm_nl_ctl set 10.0.1.1 flags nobackup
dump="id 1 flags subflow 10.0.1.1"
check "ip netns exec $ns1 ./pm_nl_ctl dump" "${dump}" "          (nobackup)"

# fullmesh support has been added later
ip netns exec $ns1 ./pm_nl_ctl set id 1 flags fullmesh 2>/dev/null
if ip netns exec $ns1 ./pm_nl_ctl dump | grep -q "fullmesh" ||
   mptcp_lib_expect_all_features; then
	dump="id 1 flags subflow,fullmesh 10.0.1.1"
	check "ip netns exec $ns1 ./pm_nl_ctl dump" "${dump}" "          (fullmesh)"
	ip netns exec $ns1 ./pm_nl_ctl set id 1 flags nofullmesh
	dump="id 1 flags subflow 10.0.1.1"
	check "ip netns exec $ns1 ./pm_nl_ctl dump" "${dump}" "          (nofullmesh)"
	ip netns exec $ns1 ./pm_nl_ctl set id 1 flags backup,fullmesh
	dump="id 1 flags subflow,backup,fullmesh 10.0.1.1"
	check "ip netns exec $ns1 ./pm_nl_ctl dump" "${dump}" "          (backup,fullmesh)"
else
	for st in fullmesh nofullmesh backup,fullmesh; do
		st="          (${st})"
		mptcp_lib_print_title "${st}"
		mptcp_lib_pr_skip
		mptcp_lib_result_skip "${st}"
	done
fi

mptcp_lib_result_print_all_tap
exit $ret
