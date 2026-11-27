#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(dirname "${0}")/mptcp_lib.sh"

mptcp_lib_check_mptcp

BIN="$(dirname "${0}")/msg_zerocopy"
if ! "${BIN}" -4 -t 1 check || ! "${BIN}" -4 -t 1 check -z; then
	mptcp_lib_pr_skip "MPTCP zerocopy not supported"
	mptcp_lib_fail_if_expected_feature "MPTCP zerocopy"
	exit "${KSFT_SKIP}"
fi

exec "$(dirname "${0}")/../msg_zerocopy.sh" "$@"
