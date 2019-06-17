#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

tmpin=$(mktemp)
tmpout=$(mktemp)

cleanup()
{
	rm -f "$tmpin" "$tmpout"
}

check_transfer()
{
	cl_proto=${1}
	srv_proto=${2}

	printf "%-8s -> %-8s socket\t\t" ${cl_proto} ${srv_proto}

	./mptcp_connect -c ${cl_proto} -p 43212 -s ${srv_proto} 127.0.0.1  < "$tmpin" > "$tmpout" 2>/dev/null
	ret=$?
	if [ ${ret} -ne 0 ]; then
		echo "[ FAIL ]"
		echo " exit code ${ret}"
		return ${ret}
	fi
	cmp "$tmpin" "$tmpout" > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "[ FAIL ]"
		ls -l "$tmpin" "$tmpout" 1>&2
	else
		echo "[  OK  ]"
	fi
}

trap cleanup EXIT

SIZE=$((RANDOM % (1024 * 1024)))
if [ $SIZE -eq 0 ]; then
	SIZE=1
fi

dd if=/dev/urandom of="$tmpin" bs=1 count=$SIZE 2> /dev/null

check_transfer MPTCP MPTCP
check_transfer MPTCP TCP
check_transfer TCP MPTCP

exit 0
