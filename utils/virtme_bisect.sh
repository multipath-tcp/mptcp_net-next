#! /bin/bash -ex

: "${MODE:=normal}"
: "${STRESS:=0}"
: "${STRESS_IN:=0}"
: "${PRIO:=0}"
: "${STASH:=0}"
: "${STASH_IGNORE_CONFLICTS:=0}"
: "${FIND_FIX:=0}"

wait_vm() { local i=0
	while [[ $((i++)) -lt "${1}" ]]; do
		# shellcheck disable=SC2009 # we grep on the args
		ps aux | grep -q "[v]irtme_hostname=" && break
		sleep 5s
	done
	sleep "${2}"
}

stress() { local pid nproc2
	wait_vm 500 30

	nproc2=$(nproc); nproc2=$((nproc2 * 2))
	stress-ng --cpu "${nproc2}" --iomix "${nproc2}" --vm "${nproc2}" --vm-bytes 1G --timeout 60m &
	pid=$!

	echo -e "\n\n=== Stress in progress (${pid}) ===\n"
	wait ${pid} || true
}

stress_in() { local envs=() env pid
	wait_vm 500 30

	for env in "${!INPUT_@}"; do envs+=(-e "${env}=${!env}"); done
	docker exec "$(docker ps --filter "label=name=mptcp-upstream-virtme-docker" -l --format "{{.ID}}")" \
		/entrypoint.sh connect stress-ng --cpu "0" --iomix "0" --vm "0" --vm-bytes "1G" &
	pid=$!

	echo -e "\n\n=== Stress (in) in progress (${pid}) ===\n"
	wait ${pid} || true
}

prio() { local envs=() env
	wait_vm 500 20

	for env in "${!INPUT_@}"; do envs+=(-e "${env}=${!env}"); done
	docker exec "$(docker ps --filter "label=name=mptcp-upstream-virtme-docker" -l --format "{{.ID}}")" \
		bash -c "renice -n ${PRIO} -p \$(pidof qemu-system-x86_64)" || true
}

exit_trap() {
	local rc=$?

	echo -e "${0}: exit trap rc=${rc} (stress: ${STRESS} ; $(jobs -p))"

	docker ps --filter ancestor=mptcp/mptcp-upstream-virtme-docker --format='{{.ID}}' | xargs -r docker stop
	jobs -p | xargs -r kill || true
	[ "${STRESS}" = 1  ] && { pkill stress-ng || true; }
	sleep 1

	[ "${STASH}" = 1 ] && git stash

	return ${rc}
}

if [ "${STASH}" = 1 ]; then
	if ! git stash pop; then
		git --no-pager diff
		echo "========= Conflict with git stash pop ========="
		git restore --staged --worktree . || true
		if [ "${STASH_IGNORE_CONFLICTS}" = 1 ]; then
			echo "==> ignore git stash and continue"
		else
			echo "==> skip commit"
			exit 125 # skip
		fi
	fi
fi

trap 'exit_trap' EXIT

export VIRTME_NO_INTERACTIVE=1

#SUFFIX=$(make kernelversion | cut -d. -f1-2)
SUFFIX=tmp  # not to polute others, or to create too many different ones

DEFAULT_ARG_BUILD=(-d WERROR)
VIRTME_PACKETDRILL_STABLE=1 \
	INPUT_BUILD_SKIP_PERF=1 \
	INPUT_CLEAN=1 \
	INPUT_BUILD_SUFFIX=${SUFFIX} \
	./.virtme.sh "build" "${MODE}" "${@:-${DEFAULT_ARG_BUILD[@]}}" &
PID_VIRTME=$!
wait ${PID_VIRTME} || exit 125 # skip

INPUT_BUILD_SUFFIX=${SUFFIX} \
	./.virtme.sh "vm-auto" "${MODE}" &
PID_VIRTME=$!

if [ "${STRESS}" != 0 ]; then
	stress &
fi
if [ "${STRESS_IN}" != 0 ]; then
	stress_in &
fi
if [ "${PRIO}" != 0 ]; then
	prio &
fi

rc=0
wait ${PID_VIRTME} || rc=${?}

if [ "${FIND_FIX}" = 1 ] && [ "${rc}" != 125 ]; then
	[ "${rc}" != 0 ] ## good is bad, bad is good
else
	exit ${rc}
fi
