#!/bin/bash
if [ -f .topmsg ]; then
	./.title.sh
else
	git log --oneline --no-decorate -1 HEAD
fi

echo | ./scripts/config --enable MPTCP
#echo | ./scripts/config --disable MPTCP || true

make -j$(nproc)
