#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# Double quotes to prevent globbing and word splitting is recommended in new
# code but we accept it, especially because there were too many before having
# address all other issues detected by shellcheck.
#shellcheck disable=SC2086

. "$(dirname "${0}")/mptcp_lib.sh"

ret=0

usage() {
	echo "Usage: $0 [ -i ] [ -h ]"
	echo -e "\t-i: use 'ip mptcp' instead of 'pm_nl_ctl'"
	echo -e "\t-h: help"
}

optstring=hi
while getopts "$optstring" option;do
	case "$option" in
	"h")
		usage $0
		exit ${KSFT_PASS}
		;;
	"i")
		mptcp_lib_set_ip_mptcp
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

check "mptcp_lib_endpoint_ops show ${ns1}" "" "defaults addr list"

default_limits="$(mptcp_lib_endpoint_ops limits "${ns1}")"
if mptcp_lib_expect_all_features; then
	limits=$'accept 0\nsubflows 2'
	mptcp_lib_is_ip_mptcp && limits="add_addr_accepted 0 subflows 2 "
	check "mptcp_lib_endpoint_ops limits ${ns1}" "${limits}" "defaults limits"
fi

mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.1
mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.2 flags subflow dev lo
mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.3 flags signal,backup
endpoint="id 1 flags  10.0.1.1"
mptcp_lib_is_ip_mptcp && endpoint="10.0.1.1 id 1 "
check "mptcp_lib_endpoint_ops show ${ns1} 1" "${endpoint}" "simple add/get addr"

dump="$(printf '%s\n' \
	"id 1 flags  10.0.1.1" \
	"id 2 flags subflow dev lo 10.0.1.2" \
	"id 3 flags signal,backup 10.0.1.3")"
mptcp_lib_is_ip_mptcp && \
dump="$(printf '%s\n' \
	"10.0.1.1 id 1 " \
	"10.0.1.2 id 2 subflow dev lo " \
	"10.0.1.3 id 3 signal backup ")"
check "mptcp_lib_endpoint_ops show ${ns1}" \
	"${dump}" "dump addrs"

mptcp_lib_endpoint_ops del "${ns1}" 2
dump=$'id 1 flags  10.0.1.1\nid 3 flags signal,backup 10.0.1.3'
mptcp_lib_is_ip_mptcp && dump=$'10.0.1.1 id 1 \n10.0.1.3 id 3 signal backup '
check "mptcp_lib_endpoint_ops show ${ns1} 2" "" "simple del addr"
check "mptcp_lib_endpoint_ops show ${ns1}" \
	"${dump}" "dump addrs after del"

mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.3 2>/dev/null
check "mptcp_lib_endpoint_ops show ${ns1} 4" "" "duplicate addr"

mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.4 flags signal
endpoint="id 4 flags signal 10.0.1.4"
mptcp_lib_is_ip_mptcp && endpoint="10.0.1.4 id 4 signal "
check "mptcp_lib_endpoint_ops show ${ns1} 4" "${endpoint}" "id addr increment"

for i in $(seq 5 9); do
	mptcp_lib_endpoint_ops add "${ns1}" "10.0.1.${i}" flags signal >/dev/null 2>&1
done
endpoint="id 9 flags signal 10.0.1.9"
mptcp_lib_is_ip_mptcp && endpoint="10.0.1.9 id 9 signal "
check "mptcp_lib_endpoint_ops show ${ns1} 9" "${endpoint}" "hard addr limit"
check "mptcp_lib_endpoint_ops show ${ns1} 10" "" "above hard addr limit"

mptcp_lib_endpoint_ops del "${ns1}" 9
for i in $(seq 10 255); do
	mptcp_lib_endpoint_ops add "${ns1}" 10.0.0.9 id "${i}"
	mptcp_lib_endpoint_ops del "${ns1}" "${i}"
done
dump="$(printf '%s\n' \
	"id 1 flags  10.0.1.1" \
	"id 3 flags signal,backup 10.0.1.3" \
	"id 4 flags signal 10.0.1.4" \
	"id 5 flags signal 10.0.1.5" \
	"id 6 flags signal 10.0.1.6" \
	"id 7 flags signal 10.0.1.7" \
	"id 8 flags signal 10.0.1.8")"
mptcp_lib_is_ip_mptcp && \
dump="$(printf '%s\n' \
	"10.0.1.1 id 1 " \
	"10.0.1.3 id 3 signal backup " \
	"10.0.1.4 id 4 signal " \
	"10.0.1.5 id 5 signal " \
	"10.0.1.6 id 6 signal " \
	"10.0.1.7 id 7 signal " \
	"10.0.1.8 id 8 signal ")"
check "mptcp_lib_endpoint_ops show ${ns1}" "${dump}" "id limit"

mptcp_lib_endpoint_ops flush "${ns1}"
check "mptcp_lib_endpoint_ops show ${ns1}" "" "flush addrs"

mptcp_lib_endpoint_ops limits "${ns1}" 9 1 2>/dev/null
check "mptcp_lib_endpoint_ops limits ${ns1}" "${default_limits}" "rcv addrs above hard limit"

mptcp_lib_endpoint_ops limits "${ns1}" 1 9 2>/dev/null
check "mptcp_lib_endpoint_ops limits ${ns1}" "${default_limits}" "subflows above hard limit"

mptcp_lib_endpoint_ops limits "${ns1}" 8 8
limits=$'accept 8\nsubflows 8'
mptcp_lib_is_ip_mptcp && limits="add_addr_accepted 8 subflows 8 "
check "mptcp_lib_endpoint_ops limits ${ns1}" "${limits}" "set limits"

mptcp_lib_endpoint_ops flush "${ns1}"
mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.1
mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.2
mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.3 id 100
mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.4
mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.5 id 254
mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.6
mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.7
mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.8
dump="$(printf '%s\n' \
	"id 1 flags  10.0.1.1" \
	"id 2 flags  10.0.1.2" \
	"id 3 flags  10.0.1.7" \
	"id 4 flags  10.0.1.8" \
	"id 100 flags  10.0.1.3" \
	"id 101 flags  10.0.1.4" \
	"id 254 flags  10.0.1.5" \
	"id 255 flags  10.0.1.6")"
mptcp_lib_is_ip_mptcp && \
dump="$(printf '%s\n' \
	"10.0.1.1 id 1 " \
	"10.0.1.2 id 2 " \
	"10.0.1.7 id 3 " \
	"10.0.1.8 id 4 " \
	"10.0.1.3 id 100 " \
	"10.0.1.4 id 101 " \
	"10.0.1.5 id 254 " \
	"10.0.1.6 id 255 ")"
check "mptcp_lib_endpoint_ops show ${ns1}" "${dump}" "set ids"

mptcp_lib_endpoint_ops flush "${ns1}"
mptcp_lib_endpoint_ops add "${ns1}" 10.0.0.1
mptcp_lib_endpoint_ops add "${ns1}" 10.0.0.2 id 254
mptcp_lib_endpoint_ops add "${ns1}" 10.0.0.3
mptcp_lib_endpoint_ops add "${ns1}" 10.0.0.4
mptcp_lib_endpoint_ops add "${ns1}" 10.0.0.5 id 253
mptcp_lib_endpoint_ops add "${ns1}" 10.0.0.6
mptcp_lib_endpoint_ops add "${ns1}" 10.0.0.7
mptcp_lib_endpoint_ops add "${ns1}" 10.0.0.8
dump="$(printf '%s\n' \
	"id 1 flags  10.0.0.1" \
	"id 2 flags  10.0.0.4" \
	"id 3 flags  10.0.0.6" \
	"id 4 flags  10.0.0.7" \
	"id 5 flags  10.0.0.8" \
	"id 253 flags  10.0.0.5" \
	"id 254 flags  10.0.0.2" \
	"id 255 flags  10.0.0.3")"
mptcp_lib_is_ip_mptcp && \
dump="$(printf '%s\n' \
	"10.0.0.1 id 1 " \
	"10.0.0.4 id 2 " \
	"10.0.0.6 id 3 " \
	"10.0.0.7 id 4 " \
	"10.0.0.8 id 5 " \
	"10.0.0.5 id 253 " \
	"10.0.0.2 id 254 " \
	"10.0.0.3 id 255 ")"
check "mptcp_lib_endpoint_ops show ${ns1}" "${dump}" "wrap-around ids"

mptcp_lib_endpoint_ops flush "${ns1}"
mptcp_lib_endpoint_ops add "${ns1}" 10.0.1.1 flags subflow
mptcp_lib_endpoint_ops change "${ns1}" 10.0.1.1 backup
dump="id 1 flags subflow,backup 10.0.1.1"
mptcp_lib_is_ip_mptcp && dump="10.0.1.1 id 1 subflow backup "
check "mptcp_lib_endpoint_ops show ${ns1}" "${dump}" "set flags (backup)"
mptcp_lib_endpoint_ops change "${ns1}" 10.0.1.1 nobackup
dump="id 1 flags subflow 10.0.1.1"
mptcp_lib_is_ip_mptcp && dump="10.0.1.1 id 1 subflow "
check "mptcp_lib_endpoint_ops show ${ns1}" "${dump}" "          (nobackup)"

# fullmesh support has been added later
mptcp_lib_endpoint_ops change "${ns1}" 1 fullmesh 2>/dev/null
if mptcp_lib_endpoint_ops show "${ns1}" | grep -q "fullmesh" ||
   mptcp_lib_expect_all_features; then
	dump="id 1 flags subflow,fullmesh 10.0.1.1"
	mptcp_lib_is_ip_mptcp && dump="10.0.1.1 id 1 subflow fullmesh "
	check "mptcp_lib_endpoint_ops show ${ns1}" "${dump}" "          (fullmesh)"
	mptcp_lib_endpoint_ops change "${ns1}" 1 nofullmesh
	dump="id 1 flags subflow 10.0.1.1"
	mptcp_lib_is_ip_mptcp && dump="10.0.1.1 id 1 subflow "
	check "mptcp_lib_endpoint_ops show ${ns1}" "${dump}" "          (nofullmesh)"
	mptcp_lib_endpoint_ops change "${ns1}" 1 backup,fullmesh
	dump="id 1 flags subflow,backup,fullmesh 10.0.1.1"
	mptcp_lib_is_ip_mptcp && dump="10.0.1.1 id 1 subflow backup fullmesh "
	check "mptcp_lib_endpoint_ops show ${ns1}" "${dump}" "          (backup,fullmesh)"
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
