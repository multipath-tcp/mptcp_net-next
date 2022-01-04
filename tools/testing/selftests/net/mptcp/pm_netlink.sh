#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

ksft_skip=4
ret=0

usage() {
	echo "Usage: $0 [ -h ]"
}


while getopts "$optstring" option;do
	case "$option" in
	"h")
		usage $0
		exit 0
		;;
	"?")
		usage $0
		exit 1
		;;
	esac
done

sec=$(date +%s)
rndh=$(printf %x $sec)-$(mktemp -u XXXXXX)
ns1="ns1-$rndh"
err=$(mktemp)
ret=0

cleanup()
{
	rm -f $err
	ip netns del $ns1
}

ip -Version > /dev/null 2>&1
if [ $? -ne 0 ];then
	echo "SKIP: Could not run test without ip tool"
	exit $ksft_skip
fi

trap cleanup EXIT

ip netns add $ns1 || exit $ksft_skip
ip -net $ns1 link set lo up
ip netns exec $ns1 sysctl -q net.mptcp.enabled=1

check()
{
	local cmd="$1"
	local expected="$2"
	local msg="$3"
	local out=`$cmd 2>$err`
	local cmd_ret=$?

	printf "%-50s %s" "$msg"
	if [ $cmd_ret -ne 0 ]; then
		echo "[FAIL] command execution '$cmd' stderr "
		cat $err
		ret=1
	elif [ "$out" = "$expected" ]; then
		echo "[ OK ]"
	else
		echo -n "[FAIL] "
		echo "expected '$expected' got '$out'"
		ret=1
	fi
}

check "ip -n $ns1 mptcp endpoint show" "" "defaults addr list"
check "ip -n $ns1 mptcp limits show" "add_addr_accepted 0 subflows 2 " "defaults limits"

ip -n $ns1 mptcp endpoint add 10.0.1.1
ip -n $ns1 mptcp endpoint add 10.0.1.2 subflow dev lo
ip -n $ns1 mptcp endpoint add 10.0.1.3 signal backup
check "ip -n $ns1 mptcp endpoint show id 1" "10.0.1.1 id 1 " "simple add/get addr"

check "ip -n $ns1 mptcp endpoint show" \
"10.0.1.1 id 1 
10.0.1.2 id 2 subflow dev lo 
10.0.1.3 id 3 signal backup " "dump addrs"

ip -n $ns1 mptcp endpoint delete id 2
check "ip -n $ns1 mptcp endpoint show id 2" "" "simple del addr"
check "ip -n $ns1 mptcp endpoint show" \
"10.0.1.1 id 1 
10.0.1.3 id 3 signal backup " "dump addrs after del"

ip -n $ns1 mptcp endpoint add 10.0.1.3 >/dev/null 2>&1
check "ip -n $ns1 mptcp endpoint show id 4" "" "duplicate addr"

ip -n $ns1 mptcp endpoint add 10.0.1.4 signal
check "ip -n $ns1 mptcp endpoint show id 4" "10.0.1.4 id 4 signal " "id addr increment"

for i in `seq 5 9`; do
	ip -n $ns1 mptcp endpoint add 10.0.1.$i signal >/dev/null 2>&1
done
check "ip -n $ns1 mptcp endpoint show id 9" "10.0.1.9 id 9 signal " "hard addr limit"
check "ip -n $ns1 mptcp endpoint show id 10" "" "above hard addr limit"

ip -n $ns1 mptcp endpoint delete id 9
for i in `seq 10 255`; do
	ip -n $ns1 mptcp endpoint add 10.0.0.9 id $i
	ip -n $ns1 mptcp endpoint delete id $i
done
check "ip -n $ns1 mptcp endpoint show" "10.0.1.1 id 1 
10.0.1.3 id 3 signal backup 
10.0.1.4 id 4 signal 
10.0.1.5 id 5 signal 
10.0.1.6 id 6 signal 
10.0.1.7 id 7 signal 
10.0.1.8 id 8 signal " "id limit"

ip -n $ns1 mptcp endpoint flush
check "ip -n $ns1 mptcp endpoint dump" "" "flush addrs"

ip -n $ns1 mptcp limits set add_addr_accepted 9 subflows 1 >/dev/null 2>&1
check "ip -n $ns1 mptcp limits show" "add_addr_accepted 0 subflows 2 " "rcv addrs above hard limit"

ip -n $ns1 mptcp limits set add_addr_accepted 1 subflows 9 >/dev/null 2>&1
check "ip -n $ns1 mptcp limits show" "add_addr_accepted 0 subflows 2 " "subflows above hard limit"

ip -n $ns1 mptcp limits set add_addr_accepted 8 subflows 8
check "ip -n $ns1 mptcp limits show" "add_addr_accepted 8 subflows 8 " "set limits"

ip -n $ns1 mptcp endpoint flush
ip -n $ns1 mptcp endpoint add 10.0.1.1
ip -n $ns1 mptcp endpoint add 10.0.1.2
ip -n $ns1 mptcp endpoint add 10.0.1.3 id 100
ip -n $ns1 mptcp endpoint add 10.0.1.4
ip -n $ns1 mptcp endpoint add 10.0.1.5 id 254
ip -n $ns1 mptcp endpoint add 10.0.1.6
ip -n $ns1 mptcp endpoint add 10.0.1.7
ip -n $ns1 mptcp endpoint add 10.0.1.8
check "ip -n $ns1 mptcp endpoint show" "10.0.1.1 id 1 
10.0.1.2 id 2 
10.0.1.7 id 3 
10.0.1.8 id 4 
10.0.1.3 id 100 
10.0.1.4 id 101 
10.0.1.5 id 254 
10.0.1.6 id 255 " "set ids"

ip -n $ns1 mptcp endpoint flush
ip -n $ns1 mptcp endpoint add 10.0.0.1
ip -n $ns1 mptcp endpoint add 10.0.0.2 id 254
ip -n $ns1 mptcp endpoint add 10.0.0.3
ip -n $ns1 mptcp endpoint add 10.0.0.4
ip -n $ns1 mptcp endpoint add 10.0.0.5 id 253
ip -n $ns1 mptcp endpoint add 10.0.0.6
ip -n $ns1 mptcp endpoint add 10.0.0.7
ip -n $ns1 mptcp endpoint add 10.0.0.8
check "ip -n $ns1 mptcp endpoint show" "10.0.0.1 id 1 
10.0.0.4 id 2 
10.0.0.6 id 3 
10.0.0.7 id 4 
10.0.0.8 id 5 
10.0.0.5 id 253 
10.0.0.2 id 254 
10.0.0.3 id 255 " "wrap-around ids"

exit $ret
