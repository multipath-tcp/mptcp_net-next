#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(dirname "$0")/mptcp_lib.sh"

ret=0
trtype="${1:-mptcp}"
iopolicy=${2:-"numa"} # round-robin, queue-depth
nqn=nqn.2014-08.org.nvmexpress.${trtype}dev
ns=1
port=1234
trsvcid=4420
ns1=""
ns2=""

ns1_cleanup()
{
	mount -t configfs none /sys/kernel/config

	rm -rf /sys/kernel/config/nvmet/ports/"${port}"/subsystems/"${trtype}"subsys
	rmdir /sys/kernel/config/nvmet/ports/"${port}"
	echo 0 > /sys/kernel/config/nvmet/subsystems/"${nqn}"/namespaces/"${ns}"/enable
	echo -n 0 > /sys/kernel/config/nvmet/subsystems/"${nqn}"/namespaces/"${ns}"/device_path
	rmdir /sys/kernel/config/nvmet/subsystems/"${nqn}"/namespaces/"${ns}"
	rmdir /sys/kernel/config/nvmet/subsystems/"${nqn}"
}

ns2_cleanup()
{
	nvme disconnect -n "${nqn}" || true
}

cleanup()
{
	ip netns exec "$ns2" bash <<- EOF
		$(declare -f ns2_cleanup)
		ns2_cleanup
	EOF

	sleep 1

	ip netns exec "$ns1" bash <<- EOF
		$(declare -f ns1_cleanup)
		ns1_cleanup
	EOF

	losetup -d /dev/loop100
	rm -rf /tmp/test.raw

	mptcp_lib_ns_exit "$ns1" "$ns2"

	kill "$monitor_pid_ns1" 2>/dev/null
	wait "$monitor_pid_ns1" 2>/dev/null

	kill "$monitor_pid_ns2" 2>/dev/null
	wait "$monitor_pid_ns2" 2>/dev/null

	unset -v trtype nqn ns port trsvcid
}

init()
{
	mptcp_lib_ns_init ns1 ns2

	# ns1		ns2
	# 10.1.1.1	10.1.1.2
	# 10.1.2.1	10.1.2.2
	# 10.1.3.1	10.1.3.2
	# 10.1.4.1	10.1.4.2
	for i in {1..4}; do
		ip link add ns1eth"$i" netns "$ns1" type veth peer name ns2eth"$i" netns "$ns2"
		ip -net "$ns1" addr add 10.1."$i".1/24 dev ns1eth"$i"
		ip -net "$ns1" addr add dead:beef:"$i"::1/64 dev ns1eth"$i" nodad
		ip -net "$ns1" link set ns1eth"$i" up
		ip -net "$ns2" addr add 10.1."$i".2/24 dev ns2eth"$i"
		ip -net "$ns2" addr add dead:beef:"$i"::2/64 dev ns2eth"$i" nodad
		ip -net "$ns2" link set ns2eth"$i" up
		ip -net "$ns2" route add default via 10.1."$i".1 dev ns2eth"$i" metric 10"$i"
		ip -net "$ns2" route add default via dead:beef:"$i"::1 dev ns2eth"$i" metric 10"$i"

		# Add tc qdisc to both namespaces for bandwidth limiting
		tc -n "$ns1" qdisc add dev ns1eth"$i" root netem rate 1000mbit
		tc -n "$ns2" qdisc add dev ns2eth"$i" root netem rate 1000mbit
	done

	mptcp_lib_pm_nl_set_limits "${ns1}" 8 8

	mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.2.1 flags signal
	mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.3.1 flags signal
	mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.4.1 flags signal

	mptcp_lib_pm_nl_set_limits "${ns2}" 8 8

	mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.2.2 flags subflow
	mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.3.2 flags subflow
	mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.4.2 flags subflow

	ip -n "${ns1}" mptcp monitor &
	monitor_pid_ns1=$!
	ip -n "${ns2}" mptcp monitor &
	monitor_pid_ns2=$!
}

run_target()
{
	mount -t configfs none /sys/kernel/config

	cd /sys/kernel/config/nvmet/subsystems || exit
	mkdir -p "${nqn}"
	cd "${nqn}" || exit
	echo 1 > attr_allow_any_host
	mkdir -p namespaces/"${ns}"
	echo /dev/loop100 > namespaces/"${ns}"/device_path
	echo 1 > namespaces/"${ns}"/enable

	cd /sys/kernel/config/nvmet/ports || exit
	mkdir -p "${port}"
	cd "${port}" || exit
	echo "${trtype}" > addr_trtype
	echo ipv4 > addr_adrfam
	echo 0.0.0.0 > addr_traddr
	echo "${trsvcid}" > addr_trsvcid

	cd subsystems || exit
	ln -sf ../../../subsystems/"${nqn}" "${trtype}"subsys
}

run_host()
{
	local traddr=10.1.1.1

	echo "nvme discover -a ${traddr}"
	nvme discover -t "${trtype}" -a "${traddr}" -s "${trsvcid}"
	if [ $? -ne 0 ]; then
		return "${KSFT_FAIL}"
	fi

	echo "nvme connect"
	devname=$(nvme connect -t "${trtype}" -a "${traddr}" -s "${trsvcid}" -n "${nqn}" |
		  awk '{print $NF}')

	sleep 1

	echo "nvme list"
	nvme list

	subname=$(nvme list-subsys /dev/"${devname}"n1 |
		  grep -o 'nvme-subsys[0-9]*' | head -1)

	echo "${iopolicy}" > /sys/class/nvme-subsystem/"${subname}"/iopolicy
	cat /sys/class/nvme-subsystem/"${subname}"/iopolicy

	echo "fio randread /dev/${devname}n1"
	fio --name=global --direct=1 --norandommap --randrepeat=0 --ioengine=libaio \
	    --thread=1 --blocksize=4k --runtime=10 --time_based --rw=randread --numjobs=4 \
	    --iodepth=256 --group_reporting --size=100% --name=libaio_4_256_4k_randread \
	    --size=4m --filename=/dev/"${devname}"n1

	sleep 1

	echo "fio randwrite /dev/${devname}n1"
	fio --name=global --direct=1 --norandommap --randrepeat=0 --ioengine=libaio \
	    --thread=1 --blocksize=4k --runtime=10 --time_based --rw=randwrite --numjobs=4 \
	    --iodepth=256 --group_reporting --size=100% --name=libaio_4_256_4k_randwrite \
	    --size=4m --filename=/dev/"${devname}"n1

	nvme flush /dev/"${devname}"n1

	sleep 1
}

init
trap cleanup EXIT

dd if=/dev/zero of=/tmp/test.raw bs=1M count=0 seek=512
losetup /dev/loop100 /tmp/test.raw

run_test()
{
	export trtype nqn ns port trsvcid
	export iopolicy

	if ! ip netns exec "$ns1" bash <<- EOF
		$(declare -f run_target)
		run_target
		exit \$?
	EOF
	then
		ret="${KSFT_FAIL}"
	fi

	if ! ip netns exec "$ns2" bash <<- EOF
		$(declare -f run_host)
		run_host
		exit \$?
	EOF
	then
		ret="${KSFT_FAIL}"
	fi
}

run_test "$@"

mptcp_lib_result_print_all_tap
exit "$ret"
