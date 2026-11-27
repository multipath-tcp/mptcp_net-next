#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(dirname "${0}")/mptcp_lib.sh"

mptcp_lib_check_mptcp

exec "$(dirname "${0}")/../msg_zerocopy.sh" "$@"
