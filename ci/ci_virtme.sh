#! /bin/bash
#
# This will launch the kselftests in a virtme env
#

set -e

EXIT_RC=0
ISSUES=()

# $1: git ref
launch_virtme_ref() {
	echo " ## Virtme: Testing Git ref '${1}' ##"
	git checkout "${1}"
	bash -x patches/docker/Dockerfile.virtme.sh patches/virtme.sh
}

# $1: title ; [ $2: git ref ]
launch_virtme_ref_log() {
	if ! launch_virtme_ref "${2:-${1}}"; then
		EXIT_RC=${?}
		ISSUES+=("${1}")
	fi
}

# $1: commit title
get_commit_ref() {
	git log -1 --format="%H" --grep "^${1}$" net-next..export || true
}

# $1: commit title
launch_virtme_commit() { local ref
	ref=$(get_commit_ref "${1}")
	if [ -n "${ref}" ]; then
		launch_virtme_ref_log "${1}" "${ref}"
	else
		echo "Unable to find the commit '${1}'"
		return 1
	fi
}

# We want to test the kselftests at the end of each series we are going to send
#launch_virtme_commit "mptcp: add basic kselftest for mptcp"
#launch_virtme_commit "mptcp: cope with later TCP fallback"
#launch_virtme_commit "selftests: add test-cases for MPTCP MP_JOIN"
launch_virtme_ref_log "export"

if [ "${EXIT_RC}" -ne 0 ]; then
	echo "Errors with:"
	printf '%s\n' "${ISSUES[@]}"
	exit "${EXIT_RC}"
fi
