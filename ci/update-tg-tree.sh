#! /bin/bash
#
# The goal is to regularly sync 'net-next' branch on this repo with Davem's one.
# Then our topgit tree can be updated and the modifications can be pushed only
# after a successful build and tests. In case of problem, a notification will be
# sent to Matthieu Baerts.

# We should manage all errors in this script
set -e

# Gerrithub remote
GIT_REMOTE_GERRITHUB_NAME="origin"

# Davem remote
GIT_REMOTE_NET_NEXT_URL="git://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git"
GIT_REMOTE_NET_NEXT_BRANCH="master"

# Local repo
GIT_BRANCH_NET_NEXT="net-next"

# $@: message to display before quiting
exit_err() {
	echo "ERROR: ${*}"
	exit 1
}

# $1: branch ;  [ $2: remote, default: origin ]
git_checkout_clean() { local branch remote
	branch="${1}"
	remote="${2:-${GIT_REMOTE_GERRITHUB_NAME}}"

	git checkout -f "${branch}" || git checkout -b "${branch}" "${remote}/${branch}"

	# no need to remove .gitignored files, should be handle by git and we might
	# need these files (.config, scripts, etc.)
	git clean -fd
}

tg_update_base() {
	git_checkout_clean "${GIT_BRANCH_NET_NEXT}"

	git pull "${GIT_REMOTE_NET_NEXT_URL}" "${GIT_REMOTE_NET_NEXT_BRANCH}"
	git push "${GIT_REMOTE_GERRITHUB_NAME}" "${GIT_BRANCH_NET_NEXT}"
}

tg_update_base || exit_err "Unable to update the base"
