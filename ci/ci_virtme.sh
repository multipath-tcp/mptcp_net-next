#! /bin/bash
#
# This will launch the kselftests in a virtme env
#

set -e

# $1: git ref
launch_virtme() {
	echo " ## Virtme: Testing Git ref '${1}' ##"
	git checkout "${1}"
	bash -x patches/docker/Dockerfile.virtme.sh patches/virtme.sh || exit 42
}

# We want to test the kselftests when they are introduced and at the end of the series
INTRO_KSELFTESTS=$(git log -1 --format="%H" --grep "^mptcp: add basic kselftest for mptcp$" net-next..export || true)
if [ -n "${INTRO_KSELFTESTS}" ]; then
	launch_virtme "${INTRO_KSELFTESTS}"
else
	echo "Unable to find the commit introducing the kselftest"
	exit 1
fi

launch_virtme "export"

