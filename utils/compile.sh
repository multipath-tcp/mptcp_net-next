#!/bin/bash
if [ -f .topmsg ]; then
	./.title.sh
else
	git log --oneline --no-decorate -1 HEAD
fi

echo | ./scripts/config -e MPTCP -e MPTCP_IPV6
#echo | ./scripts/config --disable MPTCP || true

make -j$(nproc)
