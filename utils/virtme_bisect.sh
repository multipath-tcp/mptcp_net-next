#! /bin/bash

: "${MODE:=normal}"
: "${STRESS:=0}"

stress() { local i=0 pid nproc2
	while [[ $((i++)) -lt 500 ]]; do
		# shellcheck disable=SC2009 # we grep on the args
		ps aux | grep "[/]run/virtme/guesttools/virtme-init" && break
		sleep 5s
	done
	sleep 30

	nproc2=$(nproc); nproc2=$((nproc2 * 2))
	stress-ng --cpu "${nproc2}" --io "${nproc2}" --vm "${nproc2}" --vm-bytes 1G --timeout 60m &
	pid=$!

	# We can also renice 20 qemu for even more impact

	echo -e "\n\n=== Stress in progress ($i -- ${pid}) ===\n"
	wait ${pid}
}

exit_trap() {
	rc=$?

	echo -e "${0}: exit trap (stress: ${STRESS} ; $(jobs -p))"

	docker ps --filter ancestor=mptcp/mptcp-upstream-virtme-docker --format='{{.ID}}' | xargs -r docker stop
	jobs -p | xargs -r kill
	[ "${STRESS}" = 1  ] && pkill stress-ng
	sleep 1

	return ${rc}
}

trap 'exit_trap' EXIT

VIRTME_NO_INTERACTIVE=1 VIRTME_PACKETDRILL_STABLE=1 INPUT_BUILD_SKIP_PERF=1 ./.virtme.sh "expect-${MODE}" &
PID_VIRTME=$!

if [ "${STRESS}" = 1 ]; then
	stress &
fi

wait ${PID_VIRTME}
