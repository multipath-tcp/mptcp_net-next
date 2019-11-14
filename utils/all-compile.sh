#!/bin/bash
if [ -f .topmsg ]; then
	./.title.sh
else
	git log --oneline --no-decorate -1 HEAD
fi

set -e

echo | ./scripts/config -d MPTCP -d MPTCP_IPV6 || true
make -j$(nproc)

echo | ./scripts/config -e MPTCP -e MPTCP_IPV6
make -j$(nproc)
