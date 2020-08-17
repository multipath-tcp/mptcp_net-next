#! /bin/bash

# cli options
DEBUG=0
create_cgroup=0
BPF_OBJECT=""
both=0
mptcp=0
clean=0
use_mptcp=""
delay=0

# cgroup2 related data
base="/tmp"
cgroup_type="cgroup2"
cpath="${base}/${cgroup_type}"
cgroups=("client" "server")

nargs="$#"

# Parse CLI options
while [[ "$#" -gt 0 ]]
do
    case "$1" in
        -c|--cgroup)
        create_cgroup=1
        shift
        ;;
        -B|--bpf_object)
        BPF_OBJECT="${2}"
        shift
        shift
        ;;
        -b|--both)
        both=1
        shift
        ;;
        -m|--mptcp)
        mptcp=1
        shift
        ;;
        --clean)
	clean=1
        shift
        ;;
	-D|--debug)
	DEBUG=1
	shift
	;;
	-d|--delay)
	delay=1
	shift
	;;
    esac
done

#################
#### Helpers ####
#################

if [[ ${DEBUG} -eq "1" ]]
then
	info () {
		echo "[INFO] $*"
	}

	error () {
		echo "[ERROR] $*"
	}
else
	info () { :; }
	error () { :; }
fi

setup_iface() {
    ns="$4"
    ns_exec="ip netns exec $ns"

    info "Setup veth$1 interface into <$ns> netns"

    ip l set "veth$1" netns "$ns"
    $ns_exec ip l set dev veth"$1" up
    $ns_exec ip a add dev veth"$1" 10.0."$2"."$3"/24
}

kill_cgroup_procs () {
    proc_file="${cpath}/${1}/cgroup.procs"

    if [[ -f ${proc_file} ]]
    then
        # clean all old processes attached to the cgroup if any
        if [[ $(wc -l "${proc_file}" | sed -e 's/ .*$//g') -ne "0" ]]
        then
            info "Cleaning <${cgroup}> cgroup procs"
            # shellcheck disable=SC2046 # we can have multiple pid
            kill $(cat "${proc_file}")
        fi
    fi
}

clean () {
    info "Begin env cleaning"

    # delete netns if exist
    for ns in $(ip netns list | grep ns_ | sed 's/(id: [0-9]\+)//g')
    do
        ip netns del "$ns"
        info "<$ns> removed"
    done

    # if temporary cgroup2 created, remove it
    if [[ -d ${cpath} ]]
    then
        # if cgroups created, remove them
        for cgroup in "${cgroups[@]}"
        do
            dir="${cpath}/${cgroup}"
            if [[ -d  ${dir} ]]
            then
                kill_cgroup_procs "${cgroup}"
                rmdir "${dir}"
                info "${dir} removed"
            fi
        done

        umount ${cpath}
        rmdir ${cpath}

        info "${cpath} removed"
    fi

    info "End of env cleaning"
}

launch_loader () {
	info "Launching <${BPF_OBJECT}> in <${ns_name}> netns"
        LD_LIBRARY_PATH=/usr/local/lib64 ${ns_exec} "./loader" "${BPF_OBJECT}" "${cgroup}" &

        if [[ "${create_cgroup}" -eq "1" ]]
        then
	        echo $! >> "${proc_file}"
	        info "Registering loader to <${cgroup}> cgroup"
        fi
}

##############
#### Main ####
##############

# clean previous environment if any
if [[ "${clean}" -eq "1" ]]
then
    clean
    if [[ "${nargs}" -eq "1" ]]
    then
        exit $?
    fi
fi

# loader is mandatory
if [[ "${BPF_OBJECT}" = "" ]]
then
    error "No BPF object file provided, use -B <bpf object file>"
    exit 1
fi

# create cgroup2 mount point
if [[ "${create_cgroup}" -eq "1" ]]
then
	if [[ ! -d "${cpath}" ]]
	then
		info "Creating cgroup2 mounting point"
		mkdir -p $cpath
		mount -t $cgroup_type none $cpath
	fi
fi

# create veth pair for inter netns link
ip l | grep veth1 > /dev/null
if [ "$?" -eq "1" ]
then
	info "Creating veth pair(s)"
	end=2
	if [[ "$mptcp" -eq "1" ]]
	then
		use_mptcp="./mptcp-tools/use_mptcp/use_mptcp.sh"
		end=6
	fi

	for dev in $(seq 1 2 "${end}")
	do
		ip l add veth"${dev}" type veth peer name veth"$((dev+1))"
	done
fi

# setup client and server environment
i=1
for cgroup in "${cgroups[@]}"
do
	# check the presence of the cgroup
        # create it if not found
	if [[ "${create_cgroup}" -eq "1" ]]
	then
		if [[ ! -d "${cpath}/${cgroup}" ]]
		then
			info "Creating <${cgroup}> cgroup2"
			mkdir -p "${cpath}/${cgroup}"
		fi
		kill_cgroup_procs "${cgroup}"
	fi

	# check the presence of the netns
	# create it if not present
	ns_name="ns_${cgroup}"
	ns_exec="ip netns exec $ns_name"
	ip netns list | grep "${ns_name}" > /dev/null
	if [ $? -eq 1 ]
	then
		info "Creating <${ns_name}> netns"
		ip netns add "${ns_name}"

		j=1
		for dev in $(seq 1 2 "${end}")
		do
			setup_iface "$((dev + i - 1))" "$((j++))" "$i" "${ns_name}"
		done

		if [[ "$mptcp" -eq "1" ]]
		then
			info "Allowing multiple MPTCP subflows in <$ns_name> netns"
			$ns_exec ip mptcp endpoint flush
			$ns_exec ip mptcp limits set add_addr_accepted 8 subflows 8
		fi
	fi

	if [ "$cgroup" = "server" ]
	then
		$ns_exec pkill python3
		$ns_exec $use_mptcp python3 -m http.server &

		if [[ "$create_cgroup" -eq "1" ]]
		then
			echo $! >> "$proc_file"
			info "Registering HTTP server to <$cgroup> cgroup"
		fi


		if [[ "${both}" -eq "1" ]]
		then
			launch_loader
		fi

		if [[ "${delay}" -eq "1" ]]
		then
			$ns_exec tc qdisc add dev veth$i root netem delay 1000ms
		fi

	else # client env

		if [[ "$mptcp" -eq "1" ]]
		then
			IFS=' ' read -r -a addrs <<< "$($ns_exec ip a show type veth scope global up | grep inet | sed -e 's/inet//g' -e 's/\/24.*$//g' -e 's/ //g' | tr '\n' ' ')"
			for addr in "${addrs[@]:1}"
			do
				info "Advertising MPTCP subflow on ${addr}"
				$ns_exec ip mptcp endpoint add "${addr}" subflow
			done
		fi
		launch_loader
        fi

    ((i++))

done
