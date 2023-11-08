#! /bin/bash
# SPDX-License-Identifier: GPL-2.0

readonly KSFT_PASS=0
readonly KSFT_FAIL=1
readonly KSFT_SKIP=4

# shellcheck disable=SC2155 # declare and assign separately
readonly KSFT_TEST=$(basename "${0}" | sed 's/\.sh$//g')

MPTCP_LIB_SUB_ESTABLISHED=10 # MPTCP_EVENT_SUB_ESTABLISHED
MPTCP_LIB_LISTENER_CREATED=15 #MPTCP_EVENT_LISTENER_CREATED
MPTCP_LIB_LISTENER_CLOSED=16  #MPTCP_EVENT_LISTENER_CLOSED

readonly AF_INET=2
readonly AF_INET6=10

MPTCP_LIB_SUBTESTS=()

# only if supported (or forced) and not disabled, see no-color.org
if { [ -t 1 ] || [ "${SELFTESTS_MPTCP_LIB_COLOR_FORCE:-}" = "1" ]; } &&
   [ "${NO_COLOR:-}" != "1" ]; then
	readonly MPTCP_LIB_COLOR_RED="\E[1;31m"
	readonly MPTCP_LIB_COLOR_GREEN="\E[1;32m"
	readonly MPTCP_LIB_COLOR_YELLOW="\E[1;33m"
	readonly MPTCP_LIB_COLOR_BLUE="\E[1;34m"
	readonly MPTCP_LIB_COLOR_RESET="\E[0m"
else
	readonly MPTCP_LIB_COLOR_RED=
	readonly MPTCP_LIB_COLOR_GREEN=
	readonly MPTCP_LIB_COLOR_YELLOW=
	readonly MPTCP_LIB_COLOR_BLUE=
	readonly MPTCP_LIB_COLOR_RESET=
fi

# mptcp_lib_echo_*: do not output the trailing newline
# $1: color, $2: text
mptcp_lib_echo_color() {
	echo -n -e "${MPTCP_LIB_START_PRINT:-}${*}${MPTCP_LIB_COLOR_RESET}"
}

mptcp_lib_echo_ok() {
	mptcp_lib_echo_color "${MPTCP_LIB_COLOR_GREEN}${*}"
}

mptcp_lib_echo_warn() {
	mptcp_lib_echo_color "${MPTCP_LIB_COLOR_YELLOW}${*}"
}

mptcp_lib_echo_info() {
	mptcp_lib_echo_color "${MPTCP_LIB_COLOR_BLUE}${*}"
}

mptcp_lib_echo_err() {
	mptcp_lib_echo_color "${MPTCP_LIB_COLOR_RED}${*}"
}

# mptcp_lib_print_*: output with EOL
mptcp_lib_print_ok() {
	mptcp_lib_echo_ok "${*}\n"
}

mptcp_lib_print_warn() {
	mptcp_lib_echo_warn "${*}\n"
}

mptcp_lib_print_info() {
	mptcp_lib_echo_info "${*}\n"
}

mptcp_lib_print_err() {
	mptcp_lib_echo_err "${*}\n"
}

# SELFTESTS_MPTCP_LIB_EXPECT_ALL_FEATURES env var can be set when validating all
# features using the last version of the kernel and the selftests to make sure
# a test is not being skipped by mistake.
mptcp_lib_expect_all_features() {
	[ "${SELFTESTS_MPTCP_LIB_EXPECT_ALL_FEATURES:-}" = "1" ]
}

# $1: msg
mptcp_lib_fail_if_expected_feature() {
	if mptcp_lib_expect_all_features; then
		echo "ERROR: missing feature: ${*}"
		exit ${KSFT_FAIL}
	fi

	return 1
}

# $1: file
mptcp_lib_has_file() {
	local f="${1}"

	if [ -f "${f}" ]; then
		return 0
	fi

	mptcp_lib_fail_if_expected_feature "${f} file not found"
}

mptcp_lib_check_mptcp() {
	if ! mptcp_lib_has_file "/proc/sys/net/mptcp/enabled"; then
		echo "SKIP: MPTCP support is not available"
		exit ${KSFT_SKIP}
	fi
}

mptcp_lib_check_kallsyms() {
	if ! mptcp_lib_has_file "/proc/kallsyms"; then
		echo "SKIP: CONFIG_KALLSYMS is missing"
		exit ${KSFT_SKIP}
	fi
}

# Internal: use mptcp_lib_kallsyms_has() instead
__mptcp_lib_kallsyms_has() {
	local sym="${1}"

	mptcp_lib_check_kallsyms

	grep -q " ${sym}" /proc/kallsyms
}

# $1: part of a symbol to look at, add '$' at the end for full name
mptcp_lib_kallsyms_has() {
	local sym="${1}"

	if __mptcp_lib_kallsyms_has "${sym}"; then
		return 0
	fi

	mptcp_lib_fail_if_expected_feature "${sym} symbol not found"
}

# $1: part of a symbol to look at, add '$' at the end for full name
mptcp_lib_kallsyms_doesnt_have() {
	local sym="${1}"

	if ! __mptcp_lib_kallsyms_has "${sym}"; then
		return 0
	fi

	mptcp_lib_fail_if_expected_feature "${sym} symbol has been found"
}

# !!!AVOID USING THIS!!!
# Features might not land in the expected version and features can be backported
#
# $1: kernel version, e.g. 6.3
mptcp_lib_kversion_ge() {
	local exp_maj="${1%.*}"
	local exp_min="${1#*.}"
	local v maj min

	# If the kernel has backported features, set this env var to 1:
	if [ "${SELFTESTS_MPTCP_LIB_NO_KVERSION_CHECK:-}" = "1" ]; then
		return 0
	fi

	v=$(uname -r | cut -d'.' -f1,2)
	maj=${v%.*}
	min=${v#*.}

	if   [ "${maj}" -gt "${exp_maj}" ] ||
	   { [ "${maj}" -eq "${exp_maj}" ] && [ "${min}" -ge "${exp_min}" ]; }; then
		return 0
	fi

	mptcp_lib_fail_if_expected_feature "kernel version ${1} lower than ${v}"
}

__mptcp_lib_result_add() {
	local result="${1}"
	shift

	local id=$((${#MPTCP_LIB_SUBTESTS[@]} + 1))

	MPTCP_LIB_SUBTESTS+=("${result} ${id} - ${KSFT_TEST}: ${*}")
}

# $1: test name
mptcp_lib_result_pass() {
	__mptcp_lib_result_add "ok" "${1}"
}

# $1: test name
mptcp_lib_result_fail() {
	__mptcp_lib_result_add "not ok" "${1}"
}

# $1: test name
mptcp_lib_result_skip() {
	__mptcp_lib_result_add "ok" "${1} # SKIP"
}

# $1: result code ; $2: test name
mptcp_lib_result_code() {
	local ret="${1}"
	local name="${2}"

	case "${ret}" in
		"${KSFT_PASS}")
			mptcp_lib_result_pass "${name}"
			;;
		"${KSFT_FAIL}")
			mptcp_lib_result_fail "${name}"
			;;
		"${KSFT_SKIP}")
			mptcp_lib_result_skip "${name}"
			;;
		*)
			echo "ERROR: wrong result code: ${ret}"
			exit ${KSFT_FAIL}
			;;
	esac
}

mptcp_lib_result_print_all_tap() {
	local subtest

	if [ ${#MPTCP_LIB_SUBTESTS[@]} -eq 0 ] ||
	   [ "${SELFTESTS_MPTCP_LIB_NO_TAP:-}" = "1" ]; then
		return
	fi

	printf "\nTAP version 13\n"
	printf "1..%d\n" "${#MPTCP_LIB_SUBTESTS[@]}"

	for subtest in "${MPTCP_LIB_SUBTESTS[@]}"; do
		printf "%s\n" "${subtest}"
	done
}

# get the value of keyword $1 in the line marked by keyword $2
mptcp_lib_get_info_value() {
	grep "${2}" | sed -n 's/.*\('"${1}"':\)\([0-9a-f:.]*\).*$/\2/p;q'
}

# $1: info name ; $2: evts_ns ; $3: event type
mptcp_lib_evts_get_info() {
	mptcp_lib_get_info_value "${1}" "^type:${3:-1}," < "${2}"
}

# $1: PID
mptcp_lib_kill_wait() {
	[ "${1}" -eq 0 ] && return 0

	kill -SIGUSR1 "${1}" > /dev/null 2>&1
	kill "${1}" > /dev/null 2>&1
	wait "${1}" 2>/dev/null
}

# $1: IP address
mptcp_lib_is_v6() {
	[ -z "${1##*:*}" ]
}

# $1: ns, $2: MIB counter
mptcp_lib_get_counter() {
	local ns="${1}"
	local counter="${2}"
	local count

	count=$(ip netns exec "${ns}" nstat -asz "${counter}" |
		awk 'NR==1 {next} {print $2}')
	if [ -z "${count}" ]; then
		mptcp_lib_fail_if_expected_feature "${counter} counter"
		return 1
	fi

	echo "${count}"
}

mptcp_lib_make_file() {
	local name="${1}"
	local bs="${2}"
	local size="${3}"

	dd if=/dev/urandom of="${name}" bs="${bs}" count="${size}" 2> /dev/null
	echo -e "\nMPTCP_TEST_FILE_END_MARKER" >> "${name}"
}

# $1: file
mptcp_lib_print_file_err()
{
	ls -l "${1}" 1>&2
	echo "Trailing bytes are: "
	tail -c 27 "${1}"
}

# $1: input file ; $2: output file ; $3: what kind of file
mptcp_lib_check_transfer() {
	local in="${1}"
	local out="${2}"
	local what="${3}"

	if ! cmp "$in" "$out" > /dev/null 2>&1; then
		echo "[ FAIL ] $what does not match (in, out):"
		mptcp_lib_print_file_err "$in"
		mptcp_lib_print_file_err "$out"

		return 1
	fi

	return 0
}

# $1: ns, $2: port
mptcp_lib_wait_local_port_listen() {
	local listener_ns="${1}"
	local port="${2}"

	local port_hex
	port_hex="$(printf "%04X" "${port}")"

	local _
	for _ in $(seq 10); do
		ip netns exec "${listener_ns}" cat /proc/net/tcp* | \
			awk "BEGIN {rc=1} {if (\$2 ~ /:${port_hex}\$/ && \$4 ~ /0A/) \
			     {rc=0; exit}} END {exit rc}" &&
			break
		sleep 0.1
	done
}

server_evts=""
client_evts=""
server_evts_pid=0
client_evts_pid=0

# server_evts(_pid) and client_evts(_pid) are needed
# by mptcp_lib_evts_init, _start, _kill and _remove.
mptcp_lib_evts_init() {
	: "${server_evts?}"
	: "${client_evts?}"

	if [ -z "${server_evts}" ]; then
		server_evts=$(mktemp)
	fi
	if [ -z "${client_evts}" ]; then
		client_evts=$(mktemp)
	fi
}

# $1 ns1, $2 ns2
mptcp_lib_evts_start() {
	: "${server_evts:?}"
	: "${client_evts:?}"
	: "${server_evts_pid:?}"
	: "${client_evts_pid:?}"

	local ns_1="${1}"
	local ns_2="${2}"

	:>"$server_evts"
	:>"$client_evts"

	if [ "${server_evts_pid}" -ne 0 ]; then
		mptcp_lib_kill_wait "${server_evts_pid}"
	fi
	ip netns exec "${ns_1}" ./pm_nl_ctl events >> "${server_evts}" 2>&1 &
	server_evts_pid=$!

	if [ "${client_evts_pid}" -ne 0 ]; then
		mptcp_lib_kill_wait "${client_evts_pid}"
	fi
	ip netns exec "${ns_2}" ./pm_nl_ctl events >> "${client_evts}" 2>&1 &
	client_evts_pid=$!
}

mptcp_lib_evts_kill() {
	: "${server_evts_pid:?}"
	: "${client_evts_pid:?}"

	mptcp_lib_kill_wait "${server_evts_pid}"
	mptcp_lib_kill_wait "${client_evts_pid}"

	server_evts_pid=0
	client_evts_pid=0
}

mptcp_lib_evts_remove() {
	: "${server_evts:?}"
	: "${client_evts:?}"

	rm -rf "${server_evts}" "${client_evts}"
}

# $1: var name ; $2: prev ret
mptcp_lib_check_expected_one()
{
	local var="${1}"
	local exp="e_${var}"
	local prev_ret="${2}"

	if [ "${!var}" = "${!exp}" ]
	then
		return 0
	fi

	if [ "${prev_ret}" = "0" ]
	then
		ret=1
	fi

	printf "\tExpected value for '%s': '%s', got '%s'.\n" \
		"${var}" "${!exp}" "${!var}"
	return 1
}

# $@: all var names to check
mptcp_lib_check_expected()
{
	local rc=0
	local var

	for var in "${@}"
	do
		mptcp_lib_check_expected_one "${var}" "${rc}" || rc=1
	done

	if [ ${rc} -eq 0 ]
	then
		mptcp_lib_print_ok "[ ok ]"
		return 0
	fi

	return 1
}

mptcp_lib_verify_listener_events() {
	local evt=$1
	local e_type=$2
	local e_family=$3
	local e_saddr=$4
	local e_sport=$5
	local type
	local family
	local saddr
	local sport

	type=$(mptcp_lib_evts_get_info type "$evt" "$e_type")
	family=$(mptcp_lib_evts_get_info family "$evt" "$e_type")
	if [ $family ] && [ $family = $AF_INET6 ]; then
		saddr=$(mptcp_lib_evts_get_info saddr6 "$evt" "$e_type")
	else
		saddr=$(mptcp_lib_evts_get_info saddr4 "$evt" "$e_type")
	fi
	sport=$(mptcp_lib_evts_get_info sport "$evt" "$e_type")

	mptcp_lib_check_expected "type" "family" "saddr" "sport"
}

rndh=""
ns1=""
ns2=""
ns3=""
ns4=""

mptcp_lib_init_ns() {
	local sec

	sec=$(date +%s)
	rndh=$(printf %x $sec)-$(mktemp -u XXXXXX)

	ns1="ns1-$rndh"
	ns2="ns2-$rndh"
	ns3="ns3-$rndh"
	ns4="ns4-$rndh"
}
