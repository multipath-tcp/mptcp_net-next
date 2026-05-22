#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(dirname "$0")/mptcp_lib.sh"

ret=0
trtype="${1:-mptcp}"
path="${2:-1}"
iopolicy=${3:-"numa"} # round-robin, queue-depth
loss=${4:-0}
nqn="nqn.2014-08.org.nvmexpress.${trtype}dev.$$.${RANDOM}"
ns=1
port=$((RANDOM % 10000 + 20000))
trsvcid=$((RANDOM % 64512 + 1024))
ns1=""
ns2=""
temp_file=""
loop_dev=""

export trtype path nqn ns port trsvcid
export loop_dev temp_file
export iopolicy loss

usage()
{
	cat << EOF

Usage:

	$(basename "$0") [trtype] [path] [iopolicy] [loss]

	trtype   Transport type (tcp|mptcp) - default: mptcp
	path     Number of multipath (1-4) - default: 1
	iopolicy I/O policy (numa|round-robin|queue-depth) - default: numa
	loss     Enable packet loss (0|1) - default: 0

EOF
exit ${KSFT_FAIL}
}

validate_params()
{
	if [[ ! "${trtype}" =~ ^(tcp|mptcp)$ ]]; then
		echo "Invalid trtype ${trtype}. Must be tcp or mptcp"
		usage
	fi

	if [[ ! "${path}" =~ ^[1-4]$ ]]; then
		echo "Invalid path count ${path}. Must be between 1 and 4"
		usage
	fi

	if [[ ! "${iopolicy}" =~ ^(numa|round-robin|queue-depth)$ ]]; then
		echo "Invalid iopolicy ${iopolicy}."
		usage
	fi

	if [[ ! "${loss}" =~ ^[01]$ ]]; then
		echo "Invalid loss value ${loss}. Must be 0 or 1"
		usage
	fi
}

# This function is invoked indirectly
#shellcheck disable=SC2317,SC2329
ns1_cleanup()
{
	pushd /sys/kernel/config/nvmet || exit 1

	for i in $(seq 1 "${path}"); do
		local portdir=$((port + i))

		rm -rf "ports/${portdir}/subsystems/${nqn}"
		rmdir "ports/${portdir}"
	done

	echo 0 > "subsystems/${nqn}/namespaces/${ns}/enable"
	rmdir "subsystems/${nqn}/namespaces/${ns}"
	rmdir "subsystems/${nqn}"

	popd || exit 1
}

# This function is invoked indirectly
#shellcheck disable=SC2317,SC2329
ns2_cleanup()
{
	nvme disconnect -n "${nqn}" || true
}

# This function is used in the cleanup trap
#shellcheck disable=SC2317,SC2329
cleanup()
{
	if ! ip netns exec "$ns2" bash <<- EOF
		$(declare -f ns2_cleanup)
		ns2_cleanup
	EOF
	then
		echo "ns2_cleanup failed" >&2
	fi

	sleep 1

	if ! ip netns exec "$ns1" unshare -m bash <<- EOF
		mount -t configfs none /sys/kernel/config
		$(declare -f ns1_cleanup)
		ns1_cleanup
	EOF
	then
		echo "ns1_cleanup failed" >&2
	fi

	if [ -n "${loop_dev}" ] && [ -b "${loop_dev}" ]; then
		losetup -d "${loop_dev}" 2>/dev/null || true
	fi
	rm -rf "${temp_file}"

	mptcp_lib_ns_exit "$ns1" "$ns2"

	unset -v trtype path nqn ns port trsvcid
	unset -v loop_dev temp_file
	unset -v iopolicy loss
}

# $tc_args needs word splitting to pass multiple arguments to netem
# shellcheck disable=SC2086
init()
{
	local tc_args="rate 1000mbit"

	if [ "${loss}" -eq 1 ]; then
		tc_args+=" delay 5ms loss 0.5%"
	fi

	mptcp_lib_ns_init ns1 ns2

	# ns1		ns2
	# 10.1.1.1	10.1.1.2
	# 10.1.2.1	10.1.2.2
	# 10.1.3.1	10.1.3.2
	# 10.1.4.1	10.1.4.2
	for i in {1..4}; do
		ip link add ns1eth"$i" netns "$ns1" type veth peer \
					name ns2eth"$i" netns "$ns2"
		ip -net "$ns1" addr add 10.1."$i".1/24 dev ns1eth"$i"
		ip -net "$ns1" addr add dead:beef:"$i"::1/64 \
					dev ns1eth"$i" nodad
		ip -net "$ns1" link set ns1eth"$i" up
		ip -net "$ns2" addr add 10.1."$i".2/24 dev ns2eth"$i"
		ip -net "$ns2" addr add dead:beef:"$i"::2/64 \
					dev ns2eth"$i" nodad
		ip -net "$ns2" link set ns2eth"$i" up
		ip -net "$ns2" route add default via 10.1."$i".1 \
					dev ns2eth"$i" metric 10"$i"
		ip -net "$ns2" route add default via dead:beef:"$i"::1 \
					dev ns2eth"$i" metric 10"$i"

		# Add tc qdisc to both namespaces for bandwidth limiting
		tc -n "$ns1" qdisc add dev ns1eth"$i" root netem $tc_args
		tc -n "$ns2" qdisc add dev ns2eth"$i" root netem $tc_args

		tc -n "$ns1" qdisc show dev ns1eth"$i"
		tc -n "$ns2" qdisc show dev ns2eth"$i"
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
run_target()
{
	cd /sys/kernel/config/nvmet/subsystems || exit
	mkdir -p "${nqn}"
	cd "${nqn}" || exit
	echo 1 > attr_allow_any_host
	mkdir -p namespaces/"${ns}"
	echo "${loop_dev}" > namespaces/"${ns}"/device_path
	echo 1 > namespaces/"${ns}"/enable

	# Create ${path} ports, each on a different IP address
	for i in $(seq 1 "${path}"); do
		local portdir=$((port + i))

		cd /sys/kernel/config/nvmet/ports || exit
		mkdir -p "${portdir}"
		cd "${portdir}" || exit 1
		echo "${trtype}" > addr_trtype
		echo ipv4 > addr_adrfam
		if [ "${path}" -eq 1 ]; then
			echo "0.0.0.0" > addr_traddr
		else
			echo "10.1.${i}.1" > addr_traddr
		fi
		echo "${trsvcid}" > addr_trsvcid

		mkdir -p subsystems
		ln -sf "../../subsystems/${nqn}" "subsystems/${nqn}"
		cd - >/dev/null || exit
	done
}

# This function is invoked indirectly
#shellcheck disable=SC2317,SC2329
set_io_policy()
{
	local nqn="$1"
	local iopolicy="$2"
	local subname
	local policy
	local current

	subname=$(nvme list-subsys 2>/dev/null | grep "${nqn}" |
		  grep -o 'nvme-subsys[0-9]*' | head -1)
	if [ -z "$subname" ]; then
		return 1
	fi

	policy="/sys/class/nvme-subsystem/${subname}/iopolicy"
	if [ ! -e "$policy" ]; then
		# NVMe multipath not supported, skip iopolicy setting
		return 0
	fi

	if [ ! -w "$policy" ]; then
		return 1
	fi

	if ! echo "${iopolicy}" > "$policy" 2>/dev/null; then
		return 1
	fi

	current=$(cat "$policy" 2>/dev/null)
	if [ -z "$current" ]; then
		return 1
	fi

	if [[ "$current" != *"${iopolicy}"* ]]; then
		return 1
	fi

	return 0
}

# This function is invoked indirectly
#shellcheck disable=SC2317,SC2329
run_host()
{
	local traddr=10.1.1.1
	local devname

	echo "nvme discover -a ${traddr}"
	if ! nvme discover -t "${trtype}" -a "${traddr}" \
			   -s "${trsvcid}"; then
		echo "Failed to discover ${traddr}"
		return 1
	fi

	for i in $(seq 1 "${path}"); do
		traddr=10.1.${i}.1
		echo "Connecting to ${traddr}:${trsvcid}"
		if ! nvme connect -t "${trtype}" -a "${traddr}" \
				  -s "${trsvcid}" -n "${nqn}"; then
			echo "Failed to connect to ${traddr}"
			return 1
		fi
	done

	for i in $(seq 1 10); do
		for dev in /dev/nvme*n1; do
			if [ -b "$dev" ] 2>/dev/null; then
				if nvme id-ctrl "$dev" 2>/dev/null |
				   grep -q "${nqn}"; then
					devname=$(basename "$dev")
					break 2
				fi
			fi
		done 2>/dev/null
		[ -n "$devname" ] && break
		sleep 1
	done

	if [ -z "$devname" ]; then
		echo "No block device found for NQN ${nqn}" >&2
		return 1
	fi

	echo "nvme list"
	if ! nvme list; then
		echo "nvme list failed" >&2
		return 1
	fi

	if ! set_io_policy "${nqn}" "${iopolicy}"; then
		echo "Failed to set I/O policy to ${iopolicy}"
		return 1
	fi

	sleep 1

	echo "fio randread /dev/${devname}"
	if ! fio --name=global --direct=1 --norandommap --randrepeat=0 \
		 --ioengine=libaio --thread=1 --blocksize=128k --runtime=10 \
		 --time_based --rw=randread --numjobs=4 --iodepth=256 \
		 --group_reporting --size=100% \
		 --name=libaio_4_256_128k_randread \
		 --filename="/dev/${devname}"; then
		echo "fio randread failed"
		return 1
	fi

	sleep 1

	echo "fio randwrite /dev/${devname}"
	if ! fio --name=global --direct=1 --norandommap --randrepeat=0 \
		 --ioengine=libaio --thread=1 --blocksize=128k --runtime=10 \
		 --time_based --rw=randwrite --numjobs=4 --iodepth=256 \
		 --group_reporting --size=100% \
		 --name=libaio_4_256_128k_randwrite \
		 --filename="/dev/${devname}"; then
		echo "fio randwrite failed"
		return 1
	fi

	nvme flush "/dev/${devname}"
}

mptcp_lib_check_tools nvme fio
validate_params

if ! temp_file=$(mktemp --suffix=.raw /tmp/nvme_test.XXXXXX); then
	echo "Failed to create temp file"
	exit 1
fi

trap cleanup EXIT

if ! dd if=/dev/zero of="${temp_file}" bs=1M count=0 seek=512; then
	echo "Failed to create backing file" >&2
	exit 1
fi

if ! loop_dev=$(losetup -f --show "${temp_file}"); then
	echo "Failed to create loop device" >&2
	exit 1
fi

init

run_test()
{
	if ! ip netns exec "$ns1" unshare -m bash <<- EOF
		mount -t configfs none /sys/kernel/config
		$(declare -f run_target)
		run_target
		exit \$?
	EOF
	then
		ret="${KSFT_FAIL}"
	fi

	if ! ip netns exec "$ns2" bash <<- EOF
		$(declare -f set_io_policy)
		$(declare -f run_host)
		run_host
		exit \$?
	EOF
	then
		ret="${KSFT_FAIL}"
	fi

	sleep 1
}

run_test "$@"

if [ "${ret}" -eq 0 ]; then
	mptcp_lib_result_pass "nvme over ${trtype} test"
else
	mptcp_lib_result_fail "nvme over ${trtype} test"
fi

mptcp_lib_result_print_all_tap
exit "$ret"
