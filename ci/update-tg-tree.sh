#! /bin/bash
#
# The goal is to regularly sync 'net-next' branch on this repo with Davem's one.
# Then our topgit tree can be updated and the modifications can be pushed only
# after a successful build and tests. In case of problem, a notification will be
# sent to Matthieu Baerts.

# We should manage all errors in this script
set -e

# Gerrithub remote
GIT_GERRITHUB_NAME="origin"

# Davem remote
GIT_REMOTE_NET_NEXT_URL="git://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git"
GIT_REMOTE_NET_NEXT_NAME="net-next"
GIT_REMOTE_NET_NEXT_BRANCH="master"

# Local repo
GIT_BRANCH_NET_NEXT="net-next"

# $@: message to display before quiting
exit_err() {
	echo "ERROR: ${*}"
	exit 1
}

tg_update_base() {
	if ! git remote show "${GIT_REMOTE_NET_NEXT_NAME}" | grep -q "${GIT_REMOTE_NET_NEXT_URL}"; then
		git remote add "${GIT_REMOTE_NET_NEXT_NAME}" "${GIT_REMOTE_NET_NEXT_URL}"
	fi

	git checkout "${GIT_BRANCH_NET_NEXT}"
	git pull "${GIT_REMOTE_NET_NEXT_NAME}" "${GIT_REMOTE_NET_NEXT_BRANCH}"
	git push "${GIT_GERRITHUB_NAME}" "${GIT_BRANCH_NET_NEXT}"
}

tg_update_base || exit_err "Unable to update the base"
