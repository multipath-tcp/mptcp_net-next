#! /bin/bash

TRACEFS="/sys/kernel/debug/tracing"
BPF_OBJECT="mptcp_set_sf_sockopt_kern.o"
USE_MPTCP="mptcp-tools/use_mptcp/use_mptcp.sh"
NS_EXEC="ip netns exec"
NS_CLIENT_EXEC="${NS_EXEC} ns_client"
CLIENT_PROCS="/tmp/cgroup2/client/cgroup.procs"
TCPDUMP_DUMP="/tmp/tcpdump.log"

info () {
	echo -e "\n[INFO] ${*}"
}

show () {
	while [ 1 ]
    do
        ${NS_EXEC} $1 ss -bit --cgroup
        sleep 0.25
    done
}

# clean previous trace
echo > "${TRACEFS}/trace"

# setup testing env and load BPF program on client side
./env.sh --clean -c -m -B "${BPF_OBJECT}"

# wait for end of setup
sleep 5

# load output filtering rules on client side
${NS_CLIENT_EXEC} nft -f client.rules

# show server socket status
show ns_server &
SPID="${!}"

# register current process to the client cgroup
echo $$ >> "${CLIENT_PROCS}"

# show client socket status
show ns_client &
CPID="${!}"

# launch tcpdump on client side
${NS_CLIENT_EXEC} tcpdump -Uni any -w "${TCPDUMP_DUMP}" tcp &
TPID="${!}"

# wait for tcpdump launch
sleep 5

# querying server
${NS_CLIENT_EXEC} "${USE_MPTCP}" curl 10.0.1.2:8000 -o /dev/null &> /dev/null

# unregister current process from the client cgroup
echo 0 >> "${CLIENT_PROCS}"

# kill ss wrappers and tcpdump
kill "${CPID}" "${SPID}" &> /dev/null
sleep 5
kill "${TPID}" &> /dev/null

info "Client-side tcpdump log :"
tcpdump -r "${TCPDUMP_DUMP}"

# show output filtering result
info "Client-side output filters :"
${NS_CLIENT_EXEC} nft list ruleset

# show current trace
info "Client-side bpf trace :"
cat "${TRACEFS}/trace"
