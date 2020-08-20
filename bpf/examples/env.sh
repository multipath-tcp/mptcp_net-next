#! /bin/bash

# cli options
VERBOSE=0
CREATE_CGROUP=0
BPF_OBJECT=""
BOTH=0
MPTCP=0
CLEAN=0
USE_MPTCP=""
DELAY=0

# cgroup2 related data
BASE="/tmp"
CGROUP_TYPE="cgroup2"
CPATH="${BASE}/${CGROUP_TYPE}"
HOSTS=("client" "server")

# Total number of veth to create
END=2

usage () {
	echo -e "Usage: ${0} [ OPTIONS ]
where OPTIONS := { -c[group] | -m[ptcp] | [-B[PF_object] <bpf_object> ] |
		   -d[elay] <delay>] | -v[erbose] | -b[oth] | -clean }"
}

NARGS=${#}

# Parse CLI options
while [[ ${#} -gt 0 ]]
do
	case "$1" in
		-c|-cgroup)
		CREATE_CGROUP=1
		shift
		;;
		-B|-BPF_object)
		BPF_OBJECT="${2}"
		shift 2
		;;
		-b|-both)
		BOTH=1
		shift
		;;
		-m|-mptcp)
		MPTCP=1
		shift
		;;
		-clean)
		CLEAN=1
		shift
		;;
		-v|-verbose)
		VERBOSE=1
		shift
		;;
		-d|-delay)
		[[ "${2}" -gt 0 && "${2}" -le 1000 ]] && DELAY="${2}" || DELAY=0
		shift 2
		;;
		-h|-help)
		usage
		exit 0
		shift
		;;
		*)
		usage
		exit 1
		shift
		;;
	esac
done

#################
#### Helpers ####
#################

if [[ ${VERBOSE} -eq 1 ]]
then
	info () {
		echo -e "[INF] ${*}"
	}

	error () {
		echo -e "[ERR] ${*}"
	}
else
	info () { :; }
	error () { :; }
fi

setup_iface() {
	local dev="${1}"
	local subnet="${2}"
	local ip="${3}"
	local ns="${4}"
	local ns_exec="ip netns exec ${ns}"

	info "\tsetup veth${dev} interface into <${ns}> netns"

	ip l set "veth${dev}" netns "${ns}"
	${ns_exec} ip l set dev veth"${dev}" up
	${ns_exec} ip a add dev veth"${dev}" 10.0."${subnet}"."${ip}"/24
}

kill_cgroup_procs () {
	local cgroup="${1}"
	local proc_file="${CPATH}/${cgroup}/cgroup.procs"

	if [[ -f "${proc_file}" ]]
	then
		# clean all old processes attached to the cgroup if any
		if [[ $(wc -l "${proc_file}" | sed -e 's/ .*$//g') -ne 0 ]]
		then
			# shellcheck disable=SC2046 # we can have multiple pid
			if [[ $(kill $(cat "${proc_file}")) -eq 0 ]]
			then
				info "\tcleaned <${cgroup}> cgroup procs"
			else
				error "\tfailed to clean <${cgroup}> cgroup procs"
			fi
		fi
	fi
}

# check the presence of the cgroup
# create it if not found
create_cgroup() {
	local cgroup="${1}"

	if [[ ${CREATE_CGROUP} -eq 1 ]]
	then
		local dir="${CPATH}/${cgroup}"
		if [[ ! -d "${dir}" ]]
		then
			info "\tcreate <${cgroup}> cgroup2"
			mkdir -p "${dir}"
		fi
		kill_cgroup_procs "${cgroup}"
	fi
}

# check the presence of the netns
# create it if not present
create_netns() {
	local host="${1}"
	local i="${2}"

	local ns_name="ns_${host}"
	local ns_exec="ip netns exec ${ns_name}"

	ip netns list | grep "${ns_name}" > /dev/null
	if [ ${?} -eq 1 ]
	then
		info "\tcreate <${ns_name}> netns"
		ip netns add "${ns_name}"

		local j=1
		for dev in $(seq 1 2 "${END}")
		do
			setup_iface "$((dev + i - 1))" "$((j++))" "$i" "${ns_name}"
		done

		if [[ ${MPTCP} -eq 1 ]]
		then
			info "\tallow multiple MPTCP subflows in <${ns_name}> netns"
			${ns_exec} ip mptcp endpoint flush
			${ns_exec} ip mptcp limits set add_addr_accepted 8 subflows 8
		fi
	fi
}

write_cgroup() {
	if [[ ${CREATE_CGROUP} -eq 1 ]]
	then
		local op=${1}
		local cgroup=""
		local sop="unregister"

		if [[ ${op} -ne 0 && ${op} -ne 1 ]]
		then
			error "Wrong operation on cgroup"
			clean
			exit 1
		fi

		if [[ ${op} -eq 1 ]]
		then
			cgroup="${2}/"
			sop="register"
		fi

		local proc_file="${CPATH}/${cgroup}cgroup.procs"

		echo "${$}" >> "${proc_file}"
		info "\t${sop} current process (<${cgroup}> cgroup)"
	fi
}

register_to_cgroup () {
	local cgroup="${1}"

	write_cgroup 1 "${cgroup}"
}

unregister_from_cgroup () {
	write_cgroup 0
}

dump_cgroup_procs () {
	local cgroup="${1}"
	local proc_file="${CPATH}/${cgroup}/cgroup.procs"

	if [[ ${CREATE_CGROUP} -eq 1 &&
		$(wc -l "${proc_file}" | sed -e 's/ .*$//g') -ne 0 ]]
	then
		info "Registered processes in <${cgroup}> cgroup :"
		# shellcheck disable=SC2046 # we can have multiple pid
		info "$(ps -fp $(cat "${proc_file}"))"
	fi
}

check_process () {
	local pid="${1}"

	# let time to process to launch
	sleep 1

	kill -0 "${pid}" &> /dev/null
	if [[ ${?} -eq 1 ]]
	then
		error "Background process failed to start. Quit."

		# expected to be launched with current shell in specific cgroup
		unregister_from_cgroup

		# clean unachieved env
		clean
		exit 1
	fi

	info "Background process launched as expected."
}

launch_loader () {
	if [[ "${BPF_OBJECT}" != "" ]]
	then
		local host="${1}"

		local ns_name="ns_${host}"
		local ns_exec="ip netns exec ${ns_name}"

		info "Launch <${BPF_OBJECT}> in <${ns_name}> netns"
		LD_LIBRARY_PATH=/usr/local/lib64 ${ns_exec} "./loader" "${BPF_OBJECT}" "${host}" &
		check_process ${!}
	fi
}

setup_host () {
	local host="${1}"
	local ns_exec="ip netns exec ns_${host}"

	if [ "${host}" = "server" ]
	then

		register_to_cgroup "${host}"

		info "Launch server process in <${host}> netns"
		${ns_exec} pkill python3
		#shellcheck disable=SC2086 # the string may be empty
		${ns_exec} ${USE_MPTCP} python3 -m http.server &
		check_process ${!}

		if [[ ${BOTH} -eq 1 ]]
		then
			launch_loader "${host}"
		fi

		if [[ ${DELAY} -ne 0 ]]
		then
			${ns_exec} tc qdisc add dev veth2 root netem delay "${DELAY}"ms
		fi

	else # client env

		if [[ ${MPTCP} -eq 1 ]]
		then
			IFS=' ' read -r -a addrs <<< "$($ns_exec ip a show type veth scope global up | grep inet | sed -e 's/inet//g' -e 's/\/24.*$//g' -e 's/ //g' | tr '\n' ' ')"
			for addr in "${addrs[@]:1}"
			do
				info "\tadvertise MPTCP subflow on ${addr}"
				${ns_exec} ip mptcp endpoint add "${addr}" subflow
			done
		fi

		register_to_cgroup "${host}"

		launch_loader "${host}"
    fi

	unregister_from_cgroup "${host}"
}

clean () {
	info "Clean env"

	# delete netns if exist
	for ns in $(ip netns list | grep ns_ | sed 's/(id: [0-9]\+)//g')
	do
		ip netns del "${ns}"
		info "\tremoved <${ns}>"
	done

	local dir=""

	# if temporary cgroup2 created, remove it
	if [[ -d "${CPATH}" ]]
	then
		# if cgroups created, remove them
		for cgroup in "${HOSTS[@]}"
		do
			dir="${CPATH}/${cgroup}"
			if [[ -d  ${dir} ]]
			then
				kill_cgroup_procs "${cgroup}"
				rmdir "${dir}"
				info "\tremoved <${dir}>"
			fi
		done

		umount ${CPATH}
		rmdir ${CPATH}

		info "\tremoved <${CPATH}>"
	fi
}

##############
#### Main ####
##############

# clean previous environment if any
if [[ ${CLEAN} -eq 1 ]]
then
	clean
	if [[ ${NARGS} -eq 1 || (${NARGS} -eq 2 && ${VERBOSE} -eq 1 ) ]]
	then
		exit $?
	fi
fi

# create cgroup2 mount point
if [[ ${CREATE_CGROUP} -eq 1 ]]
then
	if [[ ! -d "${CPATH}" ]]
	then
		info "Create cgroup2 mounting point"
		mkdir -p "${CPATH}"
		mount -t "${CGROUP_TYPE}" none "${CPATH}"
	fi
fi

# create veth pair for inter netns link
ip l | grep veth1 > /dev/null
if [ ${?} -eq 1 ]
then
	info "Create veth pair(s)"
	if [[ ${MPTCP} -eq 1 ]]
	then
		USE_MPTCP="./mptcp-tools/use_mptcp/use_mptcp.sh"
		END=6
	fi

	for dev in $(seq 1 2 "${END}")
	do
		ip l add veth"${dev}" type veth peer name veth"$((dev+1))"
	done
fi

# setup client and server environment
IDX=1
for host in "${HOSTS[@]}"
do

	info "Setup <${host}> host"

	create_cgroup "${host}"
	create_netns "${host}" "${IDX}"

	setup_host "${host}"
	dump_cgroup_procs "${host}"

	((IDX++))

done

info "Env ready !"
