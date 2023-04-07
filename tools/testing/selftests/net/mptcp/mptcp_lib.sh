#! /bin/bash
# SPDX-License-Identifier: GPL-2.0

readonly KSFT_FAIL=1
readonly KSFT_SKIP=4

mptcp_lib_check_mptcp() {
	if [ ! -f "/proc/sys/net/mptcp/enabled" ]; then
		echo "SKIP: MPTCP support is not available"
		exit ${KSFT_SKIP}
	fi
}

mptcp_lib_check_kallsyms() {
	if [ ! -f /proc/kallsyms ]; then
		echo "SKIP: CONFIG_KALLSYMS is missing"
		exit ${KSFT_SKIP}
	fi
}

# $1: part of a symbol to look at, add '$' at the end for full name
mptcp_lib_kallsyms_has() {
	local sym="${1}"

	if ! grep -q " ${sym}" /proc/kallsyms; then
		# We want our CI to complain if a symbol is not found
		if [ "${SELFTESTS_MPTCP_LIB_EXTRA_CHECKS:-}" = "1" ]; then
			echo "ERROR: ${sym} symbol has not been found"
			exit ${KSFT_FAIL}
		fi

		return 1
	fi
}
