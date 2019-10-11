#!/bin/bash
if [ -f .topmsg ]; then
	./.title.sh
else
	git log --oneline --no-decorate -1 HEAD
fi

set -e

echo | ./scripts/config --disable MPTCP || true
make -j$(nproc)

echo | ./scripts/config --enable MPTCP
make -j$(nproc)
