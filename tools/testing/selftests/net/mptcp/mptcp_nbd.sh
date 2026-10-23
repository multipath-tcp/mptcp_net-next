#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(dirname "$0")/mptcp_lib.sh"

ret=0
trtype="${1:-mptcp}"
ns1=""
ns2=""
port=$((RANDOM % 10000 + 20000))
temp_file=""
server_pid=""

export trtype port
export temp_file server_pid

usage()
{
	cat << EOF

Usage:

	$(basename "$0") [trtype]

	trtype   Transport type (tcp|mptcp) - default: mptcp

EOF
exit ${KSFT_FAIL}
}

validate_params()
{
	if [[ ! "${trtype}" =~ ^(tcp|mptcp)$ ]]; then
		echo "Invalid trtype ${trtype}. Must be tcp or mptcp"
		usage
	fi
}

# This function is used in the cleanup trap
#shellcheck disable=SC2317,SC2329
cleanup()
{
	# Disconnect nbd device in ns2
	ip netns exec "$ns2" nbd-client -d /dev/nbd0 2>/dev/null || true

	sleep 1

	# Kill nbd-server in ns1
	if [ -n "${server_pid}" ]; then
		ip netns exec "$ns1" kill "${server_pid}" 2>/dev/null || true
	fi
	ip netns exec "$ns1" pkill -9 -f nbd-server 2>/dev/null || true

	# Clean up temp files
	if [ -n "${temp_file}" ]; then
		ip netns exec "$ns1" rm -f "${temp_file}" 2>/dev/null || true
	fi

	mptcp_lib_ns_exit "$ns1" "$ns2"

	unset -v trtype port
	unset -v temp_file server_pid
}

init()
{
	mptcp_lib_ns_init ns1 ns2

	ip netns exec "$ns1" sysctl -qw net.ipv4.tcp_reflect_tos=1

	# ns1		ns2
	# 10.1.1.1	10.1.1.2
	# 10.1.2.1	10.1.2.2
	# 10.1.3.1	10.1.3.2
	# 10.1.4.1	10.1.4.2
	for i in {1..4}; do
		ip link add ns1eth"$i" netns "$ns1" type veth peer \
			name ns2eth"$i" netns "$ns2"
		ip -net "$ns1" addr add 10.1."$i".1/24 dev ns1eth"$i"
		ip -net "$ns1" link set ns1eth"$i" up
		ip -net "$ns2" addr add 10.1."$i".2/24 dev ns2eth"$i"
		ip -net "$ns2" link set ns2eth"$i" up
		ip -net "$ns2" route add default via 10.1."$i".1 \
			dev ns2eth"$i" metric 10"$i"

		# Rate limit to 1000mbit
		tc -n "$ns1" qdisc add dev ns1eth"$i" root netem rate 1000mbit
		tc -n "$ns2" qdisc add dev ns2eth"$i" root netem rate 1000mbit
	done

	mptcp_lib_pm_nl_set_limits "${ns1}" 8 8
	mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.1.1 flags signal
	mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.2.1 flags signal
	mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.3.1 flags signal
	mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.4.1 flags signal

	mptcp_lib_pm_nl_set_limits "${ns2}" 8 8
	mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.1.2 flags subflow
	mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.2.2 flags subflow
	mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.3.2 flags subflow
	mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.4.2 flags subflow
}

# This function is invoked indirectly
#shellcheck disable=SC2317,SC2329
run_server()
{
	local conf_file="/tmp/nbd-server.conf"

	# Create backing file
	temp_file="/tmp/nbd_backing.raw"
	dd if=/dev/zero of="${temp_file}" bs=1M count=0 seek=256 2>/dev/null

	# Detect MPTCP support: native config or mptcpize fallback
	local use_mptcpize=""
	local mptcp_opt=""
	if [ "${trtype}" = "mptcp" ]; then
		if ! grep -q '"mptcp"' /usr/bin/nbd-server 2>/dev/null && \
		   ! nbd-server --help 2>&1 | grep -qi mptcp; then
			if command -v mptcpize &> /dev/null; then
				use_mptcpize="mptcpize run -d"
				echo "INFO: nbd-server lacks native MPTCP," \
					"using mptcpize"
			else
				echo "ERROR: no MPTCP support in nbd-server"
				return 1
			fi
		else
			mptcp_opt="mptcp = true"
			echo "INFO: nbd-server has native MPTCP support"
		fi
	fi

	cat > "${conf_file}" << CONF
[generic]
	port = ${port}
	listenaddr = 0.0.0.0
	${mptcp_opt}

[test]
	exportname = ${temp_file}
CONF

	# Use -n (nodaemon) and background manually for better control
	${use_mptcpize} nbd-server -C "${conf_file}" -n > /dev/null 2>&1 &
	server_pid=$!

	sleep 2

	# Verify server is running
	if ! kill -0 "${server_pid}" 2>/dev/null; then
		echo "nbd-server failed to start"
		return 1
	fi
}

# This function is invoked indirectly
#shellcheck disable=SC2317,SC2329
run_client()
{
	local extra_args=()
	local nbd_dev="/dev/nbd0"
	local server_addr="10.1.1.1"

	local use_mptcpize=""
	if [ "${trtype}" = "mptcp" ]; then
		if nbd-client 2>&1 | grep -qE "\-M|\-\-mptcp"; then
			extra_args+=("-M")
			echo "INFO: nbd-client has native MPTCP support (-M)"
		elif command -v mptcpize &> /dev/null; then
			use_mptcpize="mptcpize run -d"
			echo "INFO: nbd-client lacks native MPTCP," \
				"using mptcpize"
		else
			echo "ERROR: no MPTCP support in nbd-client"
			return 1
		fi
	fi

	# Options before positional args: -N name host port device
	if ! ${use_mptcpize} nbd-client -N test "${extra_args[@]}" \
			"${server_addr}" "${port}" "${nbd_dev}"; then
		echo "Failed to connect ${nbd_dev} to ${server_addr}"
		return 1
	fi

	sleep 1

	# Verify connection
	if ! nbd-client -c /dev/nbd0; then
		echo "nbd-client check failed"
		return 1
	fi

	return 0
}

# This function is invoked indirectly
#shellcheck disable=SC2317,SC2329
run_io_test()
{
	local nbd_dev="/dev/nbd0"

	# dd write test
	if ! dd if=/dev/urandom of="${nbd_dev}" bs=4k count=1000 \
			conv=fdatasync 2>/dev/null; then
		echo "dd write failed"
		return 1
	fi

	# dd read test
	if ! dd if="${nbd_dev}" of=/dev/null bs=4k count=1000 2>/dev/null; then
		echo "dd read failed"
		return 1
	fi

	# fio random read test
	if ! fio --name=randread --direct=1 --ioengine=libaio \
		 --blocksize=4k --runtime=10 --time_based \
		 --rw=randread --numjobs=1 --iodepth=32 \
		 --group_reporting --size=128M \
		 --filename="${nbd_dev}"; then
		echo "fio randread failed"
		return 1
	fi

	# fio random write test
	if ! fio --name=randwrite --direct=1 --ioengine=libaio \
		 --blocksize=4k --runtime=10 --time_based \
		 --rw=randwrite --numjobs=1 --iodepth=32 \
		 --group_reporting --size=128M \
		 --filename="${nbd_dev}"; then
		echo "fio randwrite failed"
		return 1
	fi

	# Verify MPTCP subflows if trtype is mptcp
	if [ "${trtype}" = "mptcp" ]; then
		local sf_total sf_max tcp_conns is_fallback
		sf_total=$(ss -Mia | grep -oP "subflows_total:\K[0-9]+" | \
			head -1)
		sf_max=$(ss -Mia | grep -oP "subflows_max:\K[0-9]+" | head -1)
		tcp_conns=$(ss -tia | grep -c "tcp-ulp-mptcp" || true)
		is_fallback=$(ss -Mia | grep -c "fallback" || true)
		if [ "${is_fallback}" -gt 0 ]; then
			echo "FAIL: MPTCP fell back to TCP!" \
				"subflows_total:${sf_total}" \
				"tcp_subflows:${tcp_conns}"
		elif [ -n "${sf_total}" ]; then
			echo "PASS: MPTCP subflows_total:${sf_total}" \
				"subflows_max:${sf_max}" \
				"tcp_subflows:${tcp_conns}"
		else
			echo "WARNING: No MPTCP subflows info found"
		fi
	fi

	return 0
}

mptcp_lib_check_tools nbd fio
validate_params

trap cleanup EXIT

init

run_test()
{
	if ! ip netns exec "$ns1" bash <<- EOF
		$(declare -f run_server)
		export trtype port
		run_server
		exit \$?
	EOF
	then
		ret="${KSFT_FAIL}"
		return
	fi

	# Get server pid for cleanup
	server_pid=$(ip netns exec "$ns1" pgrep -f "nbd-server" | head -1)

	sleep 1

	if ! ip netns exec "$ns2" bash <<- EOF
		$(declare -f run_client run_io_test)
		export trtype port
		run_client || exit 1
		run_io_test || exit 1
		exit \$?
	EOF
	then
		ret="${KSFT_FAIL}"
	fi

	sleep 1
}

run_test "$@"

if [ "${ret}" -eq 0 ]; then
	mptcp_lib_result_pass "nbd over ${trtype} test"
else
	mptcp_lib_result_fail "nbd over ${trtype} test"
fi

mptcp_lib_result_print_all_tap
exit "$ret"
