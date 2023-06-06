#! /bin/bash

: "${MODE:=normal}"
: "${STRESS:=0}"

STRESS_PID=
stress() { local i=0
	while [[ $((i++)) -lt 500 ]]; do
		# shellcheck disable=SC2009 # we grep on the args
		ps aux | grep "[/]run/virtme/guesttools/virtme-init" && break
		sleep 5s
	done
	sleep 30
	stress-ng --cpu 24 --io 24 --vm 24 --vm-bytes 1G --timeout 60m &
	STRESS_PID=$!

	echo -e "\n\n=== Stress in progress ($i -- ${STRESS_PID}) ===\n"
	wait ${STRESS_PID}
}

exit_trap() {
	rc=$?

	echo -e "${0}: exit trap (stress: ${STRESS_PID} ; $(jobs -p))"

	docker ps --filter ancestor=mptcp/mptcp-upstream-virtme-docker --format='{{.ID}}' | xargs -r docker stop
	jobs -p | xargs -r kill
	echo "${STRESS_PID}" | xargs -r kill
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
