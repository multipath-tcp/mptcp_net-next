#!/bin/bash

tmpin=$(mktemp)
tmpout=$(mktemp)

cleanup()
{
	rm -f "$tmpin" "$tmpout"
}

trap cleanup EXIT

SIZE=$((RANDOM % (1024 * 1024)))
if [ $SIZE -eq 0 ] ; then
	SIZE=1
fi

dd if=/dev/urandom of="$tmpin" bs=1 count=$SIZE 2> /dev/null
./mptcp_connect 127.0.0.1 43212 < "$tmpin" > "$tmpout"

cmp "$tmpin" "$tmpout"
if [ $? -ne 0 ] ;then
	echo "FAIL: Input and output differ" 1>&2
	ls -l "$tmpin" "$tmpout" 1>&2
	exit 1
fi

echo "PASS: Input of $SIZE passed though mptcp connection unchanged"
exit 0
