#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

ip -Version > /dev/null 2>&1
if [ $? -ne 0 ];then
	echo "SKIP: Cannot not run test without ip tool"
	exit 1
fi

ANNOUNCED=6        # MPTCP_EVENT_ANNOUNCED
REMOVED=7          # MPTCP_EVENT_REMOVED
SUB_ESTABLISHED=10 # MPTCP_EVENT_SUB_ESTABLISHED
SUB_CLOSED=11      # MPTCP_EVENT_SUB_CLOSED

AF_INET=2
AF_INET6=10

evts_pid=0
client4_pid=0
server4_pid=0
client6_pid=0
server6_pid=0
client4_token=""
server4_token=""
client6_token=""
server6_token=""
client4_port=0;
client6_port=0;
app4_port=50002
new4_port=50003
app6_port=50004
client_addr_id=${RANDOM:0:2}
server_addr_id=${RANDOM:0:2}

sec=$(date +%s)
rndh=$(printf %x $sec)-$(mktemp -u XXXXXX)
ns1="ns1-$rndh"
ns2="ns2-$rndh"

cleanup()
{
	echo "cleanup"

	# Terminate the MPTCP connection and related processes
	kill -SIGUSR1 $client4_pid > /dev/null 2>&1
	kill $server4_pid > /dev/null 2>&1
	kill -SIGUSR1 $client6_pid > /dev/null 2>&1
	kill $server6_pid > /dev/null 2>&1

	kill $evts_pid > /dev/null 2>&1

	local netns
	for netns in "$ns1" "$ns2" ;do
		ip netns del $netns
	done
}

trap cleanup EXIT

for i in "$ns1" "$ns2" ;do
	ip netns add $i || exit 1
	ip -net $i link set lo up
	ip netns exec $i sysctl -q net.mptcp.enabled=1
	ip netns exec $i sysctl -q net.mptcp.pm_type=1
done

#  "$ns1"              ns2
#     ns1eth2    ns2eth1

ip link add ns1eth2 netns "$ns1" type veth peer name ns2eth1 netns "$ns2"

ip -net "$ns1" addr add 10.0.1.1/24 dev ns1eth2
ip -net "$ns1" addr add 10.0.2.1/24 dev ns1eth2
ip -net "$ns1" addr add dead:beef:1::1/64 dev ns1eth2 nodad
ip -net "$ns1" addr add dead:beef:2::1/64 dev ns1eth2 nodad
ip -net "$ns1" link set ns1eth2 up

ip -net "$ns2" addr add 10.0.1.2/24 dev ns2eth1
ip -net "$ns2" addr add 10.0.2.2/24 dev ns2eth1
ip -net "$ns2" addr add dead:beef:1::2/64 dev ns2eth1 nodad
ip -net "$ns2" addr add dead:beef:2::2/64 dev ns2eth1 nodad
ip -net "$ns2" link set ns2eth1 up

printf "Created network namespaces ns1, ns2         \t\t\t[OK]\n"

make_file()
{
	local name=$1
	local who=$2
	local ksize=1

	dd if=/dev/urandom of="$name" bs=1024 count=$ksize 2> /dev/null
	echo -e "\nMPTCP_TEST_FILE_END_MARKER" >> "$name"
}

make_connection()
{
	local file=$(mktemp)
	make_file "$file" "client"

	local is_v6=$1
	local app_port=$app4_port
	local connect_addr="10.0.1.1"
	local listen_addr="0.0.0.0"
	if [ "$is_v6" = "v6" ]
	then
		connect_addr="dead:beef:1::1"
		listen_addr="::"
		app_port=$app6_port
	else
		is_v6="v4"
	fi

	local client_evts=$(mktemp)
	:>"$client_evts"
	ip netns exec $ns2 ./pm_nl_ctl events >> "$client_evts" 2>&1 &
	local client_evts_pid=$!
	local server_evts=$(mktemp)
	:>"$server_evts"
	ip netns exec $ns1 ./pm_nl_ctl events >> "$server_evts" 2>&1 &
	local server_evts_pid=$!
	sleep 0.1

	# Run the server
	ip netns exec $ns1 \
			./mptcp_connect -s MPTCP -w 300 -p $app_port -l $listen_addr 2>&1 > /dev/null &
	local server_pid=$!
	sleep 0.1

	# Run the client, transfer $file and stay connected to the server
	# to conduct tests
	ip netns exec $ns2 \
			./mptcp_connect -s MPTCP -w 300 -m sendfile -p $app_port $connect_addr 2>&1 > /dev/null < $file &
	local client_pid=$!
	sleep 0.1

	kill $client_evts_pid
	local client_token=$(sed -n 's/.*\(token:\)\([[:digit:]]*\).*$/\2/p;q' "$client_evts")
	local client_port=$(sed -n 's/.*\(sport:\)\([[:digit:]]*\).*$/\2/p;q' "$client_evts")

	kill $server_evts_pid
	local server_token=$(sed -n 's/.*\(token:\)\([[:digit:]]*\).*$/\2/p;q' "$server_evts")
	rm -f "$client_evts" "$server_evts" "$file"

	if [ $client_token != "" ] && [ $server_token != "" ]
	then
		printf "Established IP%s MPTCP Connection ns2 => ns1    \t\t[OK]\n" $is_v6
	else
		exit 1
	fi

	if [ "$is_v6" = "v6" ]
	then
		client6_token=$client_token
		server6_token=$server_token
		client6_port=$client_port
		client6_pid=$client_pid
		server6_pid=$server_pid
	else
		client4_token=$client_token
		server4_token=$server_token
		client4_port=$client_port
		client4_pid=$client_pid
		server4_pid=$server_pid
	fi
}

verify_announce_event()
{
	local evt=$1
	local e_type=$2
	local e_token=$3
	local e_addr=$4
	local e_id=$5
	local e_dport=$6
	local e_af=$7

	local type=$(sed -n 's/.*\(type:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
	local token=$(sed -n 's/.*\(token:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
	local addr=""
	if [ "$e_af" = "v6" ]
	then
		addr=$(sed -n 's/.*\(daddr6:\)\([0-9a-f:.]*\).*$/\2/p;q' "$evt")
	else
		addr=$(sed -n 's/.*\(daddr4:\)\([0-9.]*\).*$/\2/p;q' "$evt")
	fi
	local dport=$(sed -n 's/.*\(dport:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
	local id=$(sed -n 's/.*\(rem_id:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
        if [ "$type" = "$e_type" ] && [ "$token" = "$e_token" ] && [ "$addr" = "$e_addr" ] && [ "$dport" = "$e_dport" ] && [ "$id" = "$e_id" ]
	then
		printf "[OK]\n"
		return 0
	fi
	printf "[FAIL]\n"
	exit 1
}

test_announce()
{
	local evts=$(mktemp)
	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl events >> "$evts" 2>&1 &
	evts_pid=$!
	sleep 0.1

	local invalid_token=$(( $client4_token - 1))
	ip netns exec $ns2 ./pm_nl_ctl ann 10.0.2.2 token $invalid_token id $client_addr_id dev ns2eth1 2>&1 > /dev/null
	local type=$(sed -n 's/.*\(type:\)\([[:digit:]]*\).*$/\2/p;q' "$evts")
	printf "ADD_ADDR 10.0.2.2 (ns2) => ns1, invalid token    \t\t"
        if [ "$type" = "" ]
	then
		printf "[OK]\n"
	else
		printf "[FAIL]\n"
		exit 1
	fi

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl ann 10.0.2.2 token $client4_token id $client_addr_id dev ns2eth1 2>&1 > /dev/null
	printf "ADD_ADDR id:%d 10.0.2.2 (ns2) => ns1, reuse port \t\t" $client_addr_id
	sleep 0.1
	verify_announce_event "$evts" "$ANNOUNCED" "$server4_token" "10.0.2.2" "$client_addr_id" "$client4_port"

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl ann dead:beef:2::2 token $client6_token id $client_addr_id dev ns2eth1 2>&1 > /dev/null
	printf "ADD_ADDR6 id:%d dead:beef:2::2 (ns2) => ns1, reuse port\t\t" $client_addr_id
	sleep 0.1
	verify_announce_event "$evts" "$ANNOUNCED" "$server6_token" "dead:beef:2::2" "$client_addr_id" "$client6_port" "v6"

	:>"$evts"
	client_addr_id=$((client_addr_id+1))
	ip netns exec $ns2 ./pm_nl_ctl ann 10.0.2.2 token $client4_token id $client_addr_id dev ns2eth1 port $new4_port 2>&1 > /dev/null
	printf "ADD_ADDR id:%d 10.0.2.2 (ns2) => ns1, new port \t\t\t" $client_addr_id
	sleep 0.1
	verify_announce_event "$evts" "$ANNOUNCED" "$server4_token" "10.0.2.2" "$client_addr_id" "$new4_port"

	kill $evts_pid

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl events >> "$evts" 2>&1 &
	evts_pid=$!
	sleep 0.1

	ip netns exec $ns1 ./pm_nl_ctl ann 10.0.2.1 token $server4_token id $server_addr_id dev ns1eth2 2>&1 > /dev/null
	printf "ADD_ADDR id:%d 10.0.2.1 (ns1) => ns2, reuse port \t\t" $server_addr_id
	sleep 0.1
	verify_announce_event "$evts" "$ANNOUNCED" "$client4_token" "10.0.2.1" "$server_addr_id" "$app4_port"

	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl ann dead:beef:2::1 token $server6_token id $server_addr_id dev ns1eth2 2>&1 > /dev/null
	printf "ADD_ADDR6 id:%d dead:beef:2::1 (ns1) => ns2, reuse port\t\t" $server_addr_id
	sleep 0.1
	verify_announce_event "$evts" "$ANNOUNCED" "$client6_token" "dead:beef:2::1" "$server_addr_id" "$app6_port" "v6"

	:>"$evts"
	server_addr_id=$((server_addr_id+1))
	ip netns exec $ns1 ./pm_nl_ctl ann 10.0.2.1 token $server4_token id $server_addr_id dev ns1eth2 port $new4_port 2>&1 > /dev/null
	printf "ADD_ADDR id:%d 10.0.2.1 (ns1) => ns2, new port \t\t\t" $server_addr_id
	sleep 0.1
	verify_announce_event "$evts" "$ANNOUNCED" "$client4_token" "10.0.2.1" "$server_addr_id" "$new4_port"

	kill $evts_pid
	rm -f "$evts"
}

verify_remove_event()
{
	local evt=$1
	local e_type=$2
	local e_token=$3
	local e_id=$4

	local type=$(sed -n 's/.*\(type:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
	local token=$(sed -n 's/.*\(token:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
	local id=$(sed -n 's/.*\(rem_id:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
        if [ "$type" = "$e_type" ] && [ "$token" = "$e_token" ] && [ "$id" = "$e_id" ]
	then
		printf "[OK]\n"
		return 0
	fi
	printf "[FAIL]\n"
	exit 1
}

test_remove()
{
	local evts=$(mktemp)
	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl events >> "$evts" 2>&1 &
	evts_pid=$!
	sleep 0.1

	local invalid_token=$(( $client4_token - 1 ))
	ip netns exec $ns2 ./pm_nl_ctl rem token $invalid_token id $client_addr_id 2>&1 > /dev/null
	printf "RM_ADDR id:%d ns2 => ns1, invalid token                    \t" $client_addr_id
	local type=$(sed -n 's/.*\(type:\)\([[:digit:]]*\).*$/\2/p;q' "$evts")
	if [ "$type" = "" ]
	then
		printf "[OK]\n"
	else
		printf "[FAIL]\n"
	fi

	local invalid_id=$(( $client_addr_id + 1 ))
	ip netns exec $ns2 ./pm_nl_ctl rem token $client4_token id $invalid_id 2>&1 > /dev/null
	printf "RM_ADDR id:%d ns2 => ns1, invalid id                    \t" $invalid_id
	type=$(sed -n 's/.*\(type:\)\([[:digit:]]*\).*$/\2/p;q' "$evts")
	if [ "$type" = "" ]
	then
		printf "[OK]\n"
	else
		printf "[FAIL]\n"
	fi

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl rem token $client4_token id $client_addr_id 2>&1 > /dev/null
	printf "RM_ADDR id:%d ns2 => ns1                                \t" $client_addr_id
	sleep 0.1
	verify_remove_event "$evts" "$REMOVED" "$server4_token" "$client_addr_id"

	:>"$evts"
	client_addr_id=$(( $client_addr_id - 1 ))
	ip netns exec $ns2 ./pm_nl_ctl rem token $client4_token id $client_addr_id 2>&1 > /dev/null
	printf "RM_ADDR id:%d ns2 => ns1                                \t" $client_addr_id
	sleep 0.1
	verify_remove_event "$evts" "$REMOVED" "$server4_token" "$client_addr_id"

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl rem token $client6_token id $client_addr_id 2>&1 > /dev/null
	printf "RM_ADDR6 id:%d ns2 => ns1                               \t" $client_addr_id
	sleep 0.1
	verify_remove_event "$evts" "$REMOVED" "$server6_token" "$client_addr_id"

	kill $evts_pid

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl events >> "$evts" 2>&1 &
	evts_pid=$!
	sleep 0.1

	ip netns exec $ns1 ./pm_nl_ctl rem token $server4_token id $server_addr_id 2>&1 > /dev/null
	printf "RM_ADDR id:%d ns1 => ns2                                \t" $server_addr_id
	sleep 0.1
	verify_remove_event "$evts" "$REMOVED" "$client4_token" "$server_addr_id"

	:>"$evts"
	server_addr_id=$(( $server_addr_id - 1 ))
	ip netns exec $ns1 ./pm_nl_ctl rem token $server4_token id $server_addr_id 2>&1 > /dev/null
	printf "RM_ADDR id:%d ns1 => ns2                                \t" $server_addr_id
	sleep 0.1
	verify_remove_event "$evts" "$REMOVED" "$client4_token" "$server_addr_id"

	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl rem token $server6_token id $server_addr_id 2>&1 > /dev/null
	printf "RM_ADDR6 id:%d ns1 => ns2                               \t" $server_addr_id
	sleep 0.1
	verify_remove_event "$evts" "$REMOVED" "$client6_token" "$server_addr_id"

	kill $evts_pid
	rm -f "$evts"
}

verify_subflow_events()
{
	local evt=$1
	local e_type=$2
	local e_token=$3
	local e_family=$4
	local e_saddr=$5
	local e_daddr=$6
	local e_dport=$7
	local e_locid=$8
	local e_remid=$9
	shift 2
	local e_from=$8
	local e_to=$9

	if [ "$e_type" = "$SUB_ESTABLISHED" ]
	then
		if [ "$e_family" = "$AF_INET6" ]
		then
			printf "CREATE_SUBFLOW6 %s (%s) => %s (%s)    " $e_saddr $e_from $e_daddr $e_to
		else
			printf "CREATE_SUBFLOW %s (%s) => %s (%s)         \t" $e_saddr $e_from $e_daddr $e_to
		fi
	else
		if [ "$e_family" = "$AF_INET6" ]
		then
			printf "DESTROY_SUBFLOW6 %s (%s) => %s (%s)   " $e_saddr $e_from $e_daddr $e_to
		else
			printf "DESTROY_SUBFLOW %s (%s) => %s (%s)         \t" $e_saddr $e_from $e_daddr $e_to
		fi
	fi

	local type=$(sed -n 's/.*\(type:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
	local token=$(sed -n 's/.*\(token:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
	local family=$(sed -n 's/.*\(family:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
	local dport=$(sed -n 's/.*\(dport:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
	local locid=$(sed -n 's/.*\(loc_id:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
	local remid=$(sed -n 's/.*\(rem_id:\)\([[:digit:]]*\).*$/\2/p;q' "$evt")
	local saddr=""
	local daddr=""
	if [ "$family" = "$AF_INET6" ]
	then
		saddr=$(sed -n 's/.*\(saddr6:\)\([0-9a-f:.]*\).*$/\2/p;q' "$evt")
		daddr=$(sed -n 's/.*\(daddr6:\)\([0-9a-f:.]*\).*$/\2/p;q' "$evt")
	else
		saddr=$(sed -n 's/.*\(saddr4:\)\([0-9.]*\).*$/\2/p;q' "$evt")
		daddr=$(sed -n 's/.*\(daddr4:\)\([0-9.]*\).*$/\2/p;q' "$evt")
	fi

        if [ "$type" = "$e_type" ] && [ "$token" = "$e_token" ] && [ "$daddr" = "$e_daddr" ] && [ "$e_dport" = "$dport" ] && [ "$family" = "$e_family" ] && [ "$saddr" = "$e_saddr" ] && [ "$e_locid" = "$locid" ] && [ "$e_remid" = "$remid" ]
	then
		printf "[OK]\n"
		return 0
	fi
	printf "[FAIL]\n"
	exit 1
}

test_subflows()
{
	local evts=$(mktemp)
	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl events >> "$evts" 2>&1 &
	evts_pid=$!
	sleep 0.1

	ip netns exec $ns2 ./pm_nl_ctl ann 10.0.2.2 token $client4_token id $client_addr_id 2>&1 > /dev/null
	sleep 0.1
	printf "ADD_ADDR 10.0.2.2 (ns2) => ns1, reuse port              \t[OK]\n"

	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl csf lip 10.0.2.1 lid 23 rip 10.0.2.2 rport $client4_port token $server4_token 2>&1 > /dev/null
	sleep 0.1
	verify_subflow_events "$evts" "$SUB_ESTABLISHED" "$server4_token" "$AF_INET" "10.0.2.1" "10.0.2.2" "$client4_port" "23" "$client_addr_id" "ns1" "ns2"

	local sport=$(sed -n 's/.*\(sport:\)\([[:digit:]]*\).*$/\2/p;q' "$evts")

	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl dsf lip 10.0.2.1 lport $sport rip 10.0.2.2 rport $client4_port token $server4_token 2>&1 > /dev/null
	sleep 0.1
	verify_subflow_events "$evts" "$SUB_CLOSED" "$server4_token" "$AF_INET" "10.0.2.1" "10.0.2.2" "$client4_port" "23" "$client_addr_id" "ns1" "ns2"

	ip netns exec $ns2 ./pm_nl_ctl rem id $client_addr_id token $client4_token 2>&1 > /dev/null
	sleep 0.1

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl ann dead:beef:2::2 token $client6_token id $client_addr_id 2>&1 > /dev/null
	sleep 0.1
	printf "ADD_ADDR6 dead:beef:2::2 (ns2) => ns1, reuse port              \t[OK]\n"

	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl csf lip dead:beef:2::1 lid 23 rip dead:beef:2::2 rport $client6_port token $server6_token 2>&1 > /dev/null
	sleep 0.1
	verify_subflow_events "$evts" "$SUB_ESTABLISHED" "$server6_token" "$AF_INET6" "dead:beef:2::1" "dead:beef:2::2" "$client6_port" "23" "$client_addr_id" "ns1" "ns2"

	local sport=$(sed -n 's/.*\(sport:\)\([[:digit:]]*\).*$/\2/p;q' "$evts")

	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl dsf lip dead:beef:2::1 lport $sport rip dead:beef:2::2 rport $client6_port token $server6_token 2>&1 > /dev/null
	sleep 0.1
	verify_subflow_events "$evts" "$SUB_CLOSED" "$server6_token" "$AF_INET6" "dead:beef:2::1" "dead:beef:2::2" "$client6_port" "23" "$client_addr_id" "ns1" "ns2"

	ip netns exec $ns2 ./pm_nl_ctl rem id $client_addr_id token $client6_token 2>&1 > /dev/null
	sleep 0.1

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl ann 10.0.2.2 token $client4_token id $client_addr_id  port $new4_port 2>&1 > /dev/null
	sleep 0.1
	printf "ADD_ADDR 10.0.2.2 (ns2) => ns1, new port                \t[OK]\n"

	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl csf lip 10.0.2.1 lid 23 rip 10.0.2.2 rport $new4_port token $server4_token 2>&1 > /dev/null
	sleep 0.1
	verify_subflow_events "$evts" "$SUB_ESTABLISHED" "$server4_token" "$AF_INET" "10.0.2.1" "10.0.2.2" "$new4_port" "23" "$client_addr_id" "ns1" "ns2"

        sport=$(sed -n 's/.*\(sport:\)\([[:digit:]]*\).*$/\2/p;q' "$evts")

	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl dsf lip 10.0.2.1 lport $sport rip 10.0.2.2 rport $new4_port token $server4_token 2>&1 > /dev/null
	sleep 0.1
	verify_subflow_events "$evts" "$SUB_CLOSED" "$server4_token" "$AF_INET" "10.0.2.1" "10.0.2.2" "$new4_port" "23" "$client_addr_id" "ns1" "ns2"

	ip netns exec $ns2 ./pm_nl_ctl rem id $client_addr_id token $client4_token 2>&1 > /dev/null

	kill $evts_pid

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl events >> "$evts" 2>&1 &
	evts_pid=$!
	sleep 0.1

	ip netns exec $ns1 ./pm_nl_ctl ann 10.0.2.1 token $server4_token id $server_addr_id 2>&1 > /dev/null
	sleep 0.1
	printf "ADD_ADDR 10.0.2.1 (ns1) => ns2, reuse port              \t[OK]\n"

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl csf lip 10.0.2.2 lid 23 rip 10.0.2.1 rport $app4_port token $client4_token 2>&1 > /dev/null
	sleep 0.1
	verify_subflow_events "$evts" "$SUB_ESTABLISHED" "$client4_token" "$AF_INET" "10.0.2.2" "10.0.2.1" "$app4_port" "23" "$server_addr_id" "ns2" "ns1"

        sport=$(sed -n 's/.*\(sport:\)\([[:digit:]]*\).*$/\2/p;q' "$evts")

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl dsf lip 10.0.2.2 lport $sport rip 10.0.2.1 rport $app4_port token $client4_token 2>&1 > /dev/null
	sleep 0.1
	verify_subflow_events "$evts" "$SUB_CLOSED" "$client4_token" "$AF_INET" "10.0.2.2" "10.0.2.1" "$app4_port" "23" "$server_addr_id" "ns2" "ns1"

	ip netns exec $ns1 ./pm_nl_ctl rem id $server_addr_id token $server4_token 2>&1 > /dev/null
	sleep 0.1

	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl ann dead:beef:2::1 token $server6_token id $server_addr_id 2>&1 > /dev/null
	sleep 0.1
	printf "ADD_ADDR6 dead:beef:2::1 (ns1) => ns2, reuse port              \t[OK]\n"

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl csf lip dead:beef:2::2 lid 23 rip dead:beef:2::1 rport $app6_port token $client6_token 2>&1 > /dev/null
	sleep 0.1
	verify_subflow_events "$evts" "$SUB_ESTABLISHED" "$client6_token" "$AF_INET6" "dead:beef:2::2" "dead:beef:2::1" "$app6_port" "23" "$server_addr_id" "ns2" "ns1"

	local sport=$(sed -n 's/.*\(sport:\)\([[:digit:]]*\).*$/\2/p;q' "$evts")

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl dsf lip dead:beef:2::2 lport $sport rip dead:beef:2::1 rport $app6_port token $client6_token 2>&1 > /dev/null
	sleep 0.1
	verify_subflow_events "$evts" "$SUB_CLOSED" "$client6_token" "$AF_INET6" "dead:beef:2::2" "dead:beef:2::1" "$app6_port" "23" "$server_addr_id" "ns2" "ns1"

	ip netns exec $ns1 ./pm_nl_ctl rem id $server_addr_id token $server6_token 2>&1 > /dev/null
	sleep 0.1

	:>"$evts"
	ip netns exec $ns1 ./pm_nl_ctl ann 10.0.2.1 token $server4_token id $server_addr_id  port $new4_port 2>&1 > /dev/null
	sleep 0.1
	printf "ADD_ADDR 10.0.2.1 (ns1) => ns2, new port                \t[OK]\n"

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl csf lip 10.0.2.2 lid 23 rip 10.0.2.1 rport $new4_port token $client4_token 2>&1 > /dev/null
	sleep 0.1
	verify_subflow_events "$evts" "$SUB_ESTABLISHED" "$client4_token" "$AF_INET" "10.0.2.2" "10.0.2.1" "$new4_port" "23" "$server_addr_id" "ns2" "ns1"

        sport=$(sed -n 's/.*\(sport:\)\([[:digit:]]*\).*$/\2/p;q' "$evts")

	:>"$evts"
	ip netns exec $ns2 ./pm_nl_ctl dsf lip 10.0.2.2 lport $sport rip 10.0.2.1 rport $new4_port token $client4_token 2>&1 > /dev/null
	sleep 0.1
	verify_subflow_events "$evts" "$SUB_CLOSED" "$client4_token" "$AF_INET" "10.0.2.2" "10.0.2.1" "$new4_port" "23" "$server_addr_id" "ns2" "ns1"

	ip netns exec $ns1 ./pm_nl_ctl rem id $server_addr_id token $server4_token 2>&1 > /dev/null

	kill $evts_pid
	rm -f "$evts"
}

make_connection
make_connection "v6"
test_announce
test_remove
test_subflows
exit 0
