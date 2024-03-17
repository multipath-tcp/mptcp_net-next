#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

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
		usage "$0"
		exit ${KSFT_PASS}
		;;
	"i")
		mptcp_lib_set_ip_mptcp
		;;
	"?")
		usage "$0"
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
	rm -f "${err}"
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

check "mptcp_lib_pm_nl_show_endpoints ${ns1}" "" "defaults addr list"

default_limits="$(mptcp_lib_pm_nl_get_limits "${ns1}")"
if mptcp_lib_expect_all_features; then
	check "mptcp_lib_pm_nl_get_limits ${ns1}" \
		"$(mptcp_lib_format_limits 0 2)" "defaults limits"
fi

mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.1
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.2 flags subflow dev lo
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.3 flags signal,backup
check "mptcp_lib_pm_nl_get_endpoint ${ns1} 1" \
	"$(mptcp_lib_format_endpoints "1,10.0.1.1")" "simple add/get addr"

check "mptcp_lib_pm_nl_show_endpoints ${ns1}" \
	"$(mptcp_lib_format_endpoints "1,10.0.1.1" \
				      "2,10.0.1.2,subflow,lo" \
				      "3,10.0.1.3,signal backup")" \
	"dump addrs"

mptcp_lib_pm_nl_del_endpoint "${ns1}" 2
check "mptcp_lib_pm_nl_get_endpoint ${ns1} 2" "" "simple del addr"
check "mptcp_lib_pm_nl_show_endpoints ${ns1}" \
	"$(mptcp_lib_format_endpoints "1,10.0.1.1" \
				      "3,10.0.1.3,signal backup")" \
	"dump addrs after del"

mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.3 2>/dev/null
check "mptcp_lib_pm_nl_get_endpoint ${ns1} 4" "" "duplicate addr"

mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.4 flags signal
check "mptcp_lib_pm_nl_get_endpoint ${ns1} 4" \
	"$(mptcp_lib_format_endpoints "4,10.0.1.4,signal")" "id addr increment"

for i in $(seq 5 9); do
	mptcp_lib_pm_nl_add_endpoint "${ns1}" "10.0.1.${i}" flags signal >/dev/null 2>&1
done
check "mptcp_lib_pm_nl_get_endpoint ${ns1} 9" \
	"$(mptcp_lib_format_endpoints "9,10.0.1.9,signal")" "hard addr limit"
check "mptcp_lib_pm_nl_get_endpoint ${ns1} 10" "" "above hard addr limit"

mptcp_lib_pm_nl_del_endpoint "${ns1}" 9
for i in $(seq 10 255); do
	mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.0.9 id "${i}"
	mptcp_lib_pm_nl_del_endpoint "${ns1}" "${i}"
done
check "mptcp_lib_pm_nl_show_endpoints ${ns1}" \
	"$(mptcp_lib_format_endpoints "1,10.0.1.1" \
				      "3,10.0.1.3,signal backup" \
				      "4,10.0.1.4,signal" \
				      "5,10.0.1.5,signal" \
				      "6,10.0.1.6,signal" \
				      "7,10.0.1.7,signal" \
				      "8,10.0.1.8,signal")" \
	"id limit"

mptcp_lib_pm_nl_flush_endpoint "${ns1}"
check "mptcp_lib_pm_nl_show_endpoints ${ns1}" "" "flush addrs"

mptcp_lib_pm_nl_set_limits "${ns1}" 9 1 2>/dev/null
check "mptcp_lib_pm_nl_get_limits ${ns1}" "${default_limits}" "rcv addrs above hard limit"

mptcp_lib_pm_nl_set_limits "${ns1}" 1 9 2>/dev/null
check "mptcp_lib_pm_nl_get_limits ${ns1}" "${default_limits}" "subflows above hard limit"

mptcp_lib_pm_nl_set_limits "${ns1}" 8 8
check "mptcp_lib_pm_nl_get_limits ${ns1}" \
	"$(mptcp_lib_format_limits 8 8)" "set limits"

mptcp_lib_pm_nl_flush_endpoint "${ns1}"
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.1
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.2
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.3 id 100
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.4
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.5 id 254
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.6
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.7
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.8
check "mptcp_lib_pm_nl_show_endpoints ${ns1}" \
	"$(mptcp_lib_format_endpoints "1,10.0.1.1" \
				      "2,10.0.1.2" \
				      "3,10.0.1.7" \
				      "4,10.0.1.8" \
				      "100,10.0.1.3" \
				      "101,10.0.1.4" \
				      "254,10.0.1.5" \
				      "255,10.0.1.6")" \
	"set ids"

mptcp_lib_pm_nl_flush_endpoint "${ns1}"
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.0.1
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.0.2 id 254
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.0.3
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.0.4
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.0.5 id 253
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.0.6
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.0.7
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.0.8
check "mptcp_lib_pm_nl_show_endpoints ${ns1}" \
	"$(mptcp_lib_format_endpoints "1,10.0.0.1" \
				      "2,10.0.0.4" \
				      "3,10.0.0.6" \
				      "4,10.0.0.7" \
				      "5,10.0.0.8" \
				      "253,10.0.0.5" \
				      "254,10.0.0.2" \
				      "255,10.0.0.3")" \
	"wrap-around ids"

mptcp_lib_pm_nl_flush_endpoint "${ns1}"
mptcp_lib_pm_nl_add_endpoint "${ns1}" 10.0.1.1 flags subflow
mptcp_lib_pm_nl_change_address "${ns1}" 10.0.1.1 backup
check "mptcp_lib_pm_nl_show_endpoints ${ns1}" \
	"$(mptcp_lib_format_endpoints "1,10.0.1.1,subflow backup")" \
	"set flags (backup)"
mptcp_lib_pm_nl_change_address "${ns1}" 10.0.1.1 nobackup
check "mptcp_lib_pm_nl_show_endpoints ${ns1}" \
	"$(mptcp_lib_format_endpoints "1,10.0.1.1,subflow")" \
	"          (nobackup)"

# fullmesh support has been added later
mptcp_lib_pm_nl_change_endpoint "${ns1}" 1 fullmesh 2>/dev/null
if mptcp_lib_pm_nl_show_endpoints "${ns1}" | grep -q "fullmesh" ||
   mptcp_lib_expect_all_features; then
	check "mptcp_lib_pm_nl_show_endpoints ${ns1}" \
		"$(mptcp_lib_format_endpoints "1,10.0.1.1,subflow fullmesh")" \
		"          (fullmesh)"
	mptcp_lib_pm_nl_change_endpoint "${ns1}" 1 nofullmesh
	check "mptcp_lib_pm_nl_show_endpoints ${ns1}" \
		"$(mptcp_lib_format_endpoints "1,10.0.1.1,subflow")" \
		"          (nofullmesh)"
	mptcp_lib_pm_nl_change_endpoint "${ns1}" 1 backup,fullmesh
	check "mptcp_lib_pm_nl_show_endpoints ${ns1}" \
		"$(mptcp_lib_format_endpoints "1,10.0.1.1,subflow backup fullmesh")" \
		"          (backup,fullmesh)"
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
