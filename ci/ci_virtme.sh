#! /bin/bash
#
# This will launch the kselftests in a virtme env
#

set -e

# $1: git ref
launch_virtme_ref() {
	echo " ## Virtme: Testing Git ref '${1}' ##"
	git checkout "${1}"
	bash -x patches/docker/Dockerfile.virtme.sh patches/virtme.sh || exit 42
}

# $1: commit title
get_commit_ref() {
	git log -1 --format="%H" --grep "^${1}$" net-next..export || true
}

# $1: commit title
launch_virtme_commit() { local ref
	ref=$(get_commit_ref "${1}")
	if [ -n "${ref}" ]; then
		launch_virtme_ref "${ref}"
	else
		echo "Unable to find the commit '${1}'"
		return 1
	fi
}

# We want to test the kselftests at the end of each series we are going to send
launch_virtme_commit "mptcp: add basic kselftest for mptcp"
launch_virtme_commit "mptcp: process MP_CAPABLE data option."
launch_virtme_ref "export"

