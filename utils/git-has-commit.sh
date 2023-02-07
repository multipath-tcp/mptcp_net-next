#!/bin/bash -e

if [ "${FETCH}" != 0 ]; then
	echo "Fetching repositories"
	git fetch -q -f --multiple --tags netdev-net netdev-next
	git fetch -q origin
fi

if [ ${#} -eq 0 ]; then
	echo "Nothing to check"
fi

for c in "${@}"; do
	git log --oneline -1 "${c}"
	git branch --remote --contains "${c}" netdev-net/main netdev-next/main origin/export
	git tag --list v"[5-9]*" --contains="${c}" | sort -V | head -n1
done
