#! /bin/bash
# SPDX-License-Identifier: GPL-2.0

readonly KSFT_SKIP=4

mptcp_lib_check_mptcp() {
	if [ ! -f "/proc/sys/net/mptcp/enabled" ]; then
		echo "SKIP: MPTCP support is not available"
		exit ${KSFT_SKIP}
	fi
}
