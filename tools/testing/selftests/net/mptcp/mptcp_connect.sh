#!/bin/bash

ret=0
sin=""
sout=""
cin=""
cout=""
ksft_skip=4
capture=0

TEST_COUNT=0

cleanup()
{
	rm -f "$cin" "$cout"
	rm -f "$sin" "$sout"
	rm -f "$capout"

	for i in 1 2 3 4; do
		ip netns del ns$i
	done
}

for arg in "$@"; do
    if [ "$arg" = "-c" ]; then
	capture=1
    fi
done

ip -Version > /dev/null 2>&1
if [ $? -ne 0 ];then
	echo "SKIP: Could not run test without ip tool"
	exit $ksft_skip
fi

sin=$(mktemp)
sout=$(mktemp)
cin=$(mktemp)
cout=$(mktemp)
capout=$(mktemp)
trap cleanup EXIT

for i in 1 2 3 4;do
	ip netns add ns$i || exit $ksft_skip
	ip -net ns$i link set lo up
done

#  ns1            ns2                 ns3             ns4
# ns1eth2    ns2eth1 ns2eth3  ns3eth2   ns3eth4   ns4eth3

ip link add ns1eth2 netns ns1 type veth peer name ns2eth1 netns ns2
ip link add ns2eth3 netns ns2 type veth peer name ns3eth2 netns ns3
ip link add ns3eth4 netns ns3 type veth peer name ns4eth3 netns ns4

ip -net ns1 addr add 10.0.1.1/24 dev ns1eth2
ip -net ns1 link set ns1eth2 up
ip -net ns1 route add default via 10.0.1.2

ip -net ns2 addr add 10.0.1.2/24 dev ns2eth1
ip -net ns2 link set ns2eth1 up

ip -net ns2 addr add 10.0.2.1/24 dev ns2eth3
ip -net ns2 link set ns2eth3 up
ip -net ns2 route add default via 10.0.2.2
ip netns exec ns2 sysctl -q net.ipv4.ip_forward=1

ip -net ns3 addr add 10.0.2.2/24 dev ns3eth2
ip -net ns3 link set ns3eth2 up

ip -net ns3 addr add 10.0.3.2/24 dev ns3eth4
ip -net ns3 link set ns3eth4 up
ip -net ns3 route add default via 10.0.2.1
ip netns exec ns3 sysctl -q net.ipv4.ip_forward=1

ip -net ns4 addr add 10.0.3.1/24 dev ns4eth3
ip -net ns4 link set ns4eth3 up
ip -net ns4 route add default via 10.0.3.2

print_file_err()
{
	ls -l "$1" 1>&2
	echo "Trailing bytes are: "
	tail -c 27 "$1"
}

check_transfer()
{
	in=$1
	out=$2
	what=$3

	cmp "$in" "$out" > /dev/null 2>&1
	if [ $? -ne 0 ] ;then
		echo "[ FAIL ] $what does not match (in, out):"
		print_file_err "$in"
		print_file_err "$out"

		return 1
	fi

	return 0
}

do_transfer()
{
	listener_ns="$1"
	connector_ns="$2"
	cl_proto="$3"
	srv_proto="$4"
	connect_addr="$5"

	port=$((10000+$TEST_COUNT))
	TEST_COUNT=$((TEST_COUNT+1))

	:> "$cout"
	:> "$sout"
	:> "$capout"
	ip netns exec ${connector_ns} ping -q -c 1 $connect_addr >/dev/null
	if [ $? -ne 0 ] ; then
		echo "$listener_ns -> $connect_addr connectivity [ FAIL ]" 1>&2
		return 1
	fi

	printf "%-4s %-5s -> %-4s (%s:%d) %-5s\t" ${connector_ns} ${cl_proto} ${listener_ns} ${connect_addr} ${port} ${srv_proto}

	if [ $capture -eq 1 ]; then
	    if [ -z $SUDO_USER ] ; then
		capuser=""
	    else
		capuser="-Z $SUDO_USER"
	    fi

	    capfile="${listener_ns}-${connector_ns}-${cl_proto}-${srv_proto}-${connect_addr}.pcap"

	    ip netns exec ${listener_ns} tcpdump -i any -s 65535 -B 32768 $capuser -w $capfile > "$capout" 2>&1 &
	    cappid=$!

	    sleep 1
	fi

	ip netns exec ${listener_ns} ./mptcp_connect -t 10 -l -p $port -s ${srv_proto} 0.0.0.0 < "$sin" > "$sout" &
	spid=$!

	sleep 1

	ip netns exec ${connector_ns} ./mptcp_connect -t 10 -p $port -s ${cl_proto} $connect_addr < "$cin" > "$cout" &
	cpid=$!

	wait $cpid
	retc=$?
	wait $spid
	rets=$?

	if [ $capture -eq 1 ]; then
	    sleep 1
	    kill $cappid
	fi

	if [ ${rets} -ne 0 ] || [ ${retc} -ne 0 ]; then
		echo "[ FAIL ] client exit code $retc, server $rets" 1>&2
		echo "\nnetns ${listener_ns} socket stat for $port:" 1>&2
		ip netns exec ${listener_ns} ss -nita 1>&2 -o "sport = :$port"
		echo "\nnetns ${connector_ns} socket stat for $port:" 1>&2
		ip netns exec ${connector_ns} ss -nita 1>&2 -o "dport = :$port"

		cat "$capout"
		ret=$rets
		return 1
	fi

	check_transfer $sin $cout "file received by client"
	retc=$?
	check_transfer $cin $sout "file received by server"
	rets=$?

	if [ $retc -eq 0 ] && [ $rets -eq 0 ];then
		echo "[ OK ]"
		cat "$capout"
		return 0
	fi

	cat "$capout"
	return 1
}

make_file()
{
	name=$1
	who=$2

	SIZE=$((RANDOM % (1024 * 8)))
	TSIZE=$((SIZE * 1024))

	dd if=/dev/urandom of="$name" bs=1024 count=$SIZE 2> /dev/null

	SIZE=$((RANDOM % 1024))
	SIZE=$((SIZE + 128))
	TSIZE=$((TSIZE + SIZE))
	dd if=/dev/urandom conf=notrunc of="$name" bs=1 count=$SIZE 2> /dev/null
	echo -e "\nMPTCP_TEST_FILE_END_MARKER" >> "$name"

	echo "Created $name (size $TSIZE) containing data sent by $who"
}

run_tests()
{
        listener_ns="$1"
        connector_ns="$2"
	connect_addr="$3"

	do_transfer ${listener_ns} ${connector_ns} MPTCP MPTCP ${connect_addr}
	[ $? -ne 0 ] && return
	do_transfer ${listener_ns} ${connector_ns} MPTCP TCP ${connect_addr}
	[ $? -ne 0 ] && return
	do_transfer ${listener_ns} ${connector_ns} TCP MPTCP ${connect_addr}
}

make_file "$cin" "client"
make_file "$sin" "server"

for sender in 1 2 3 4;do
	run_tests ns1 ns$sender 10.0.1.1

	run_tests ns2 ns$sender 10.0.1.2
	run_tests ns2 ns$sender 10.0.2.1

	run_tests ns3 ns$sender 10.0.2.2
	run_tests ns3 ns$sender 10.0.3.2

	run_tests ns4 ns$sender 10.0.3.1
done

exit $ret
