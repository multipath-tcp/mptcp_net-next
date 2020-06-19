#! /bin/bash
#
# The goal is to regularly sync 'net-next' branch on this repo with netdev's one.
# Then our topgit tree can be updated and the modifications can be pushed only
# after a successful build and tests. In case of problem, a notification will be
# sent to Matthieu Baerts.

# We should manage all errors in this script
set -e

# Env vars that can be set to change the behaviour
: "${UPD_TG_FORCE_SYNC:=0}"
: "${UPD_TG_NOT_BASE:=0}"
: "${UPD_TG_VALIDATE_EACH_TOPIC:=0}"

# Github remote
GIT_REMOTE_GITHUB_NAME="origin"

# Netdev remote
GIT_REMOTE_NET_NEXT_URL="git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git"
GIT_REMOTE_NET_NEXT_BRANCH="master"

# Local repo
TG_TOPIC_BASE="net-next"
TG_TOPIC_TOP="t/upstream"
TG_TOPIC_SKIP="t/DO-NOT-MERGE-mptcp-enabled-by-default"
TG_EXPORT_BRANCH="export"
TG_FOR_REVIEW_BRANCH="for-review"

ERR_MSG=""

###########
## Utils ##
###########

# $@: message to display before quiting
err() {
	echo "ERROR: ${*}" >&2
}

# $1: last return code
print_err() { local rc
	rc="${1}"

	# check return code: if different than 0, we exit with an error: reset
	if [ "${rc}" -eq 0 ]; then
		return 0
	fi

	# in the notif, only the end is displayed
	set +x
	err "${ERR_MSG}"

	return "${rc}"
}

# $1: branch ;  [ $2: remote, default: origin ]
git_checkout() { local branch remote
	branch="${1}"
	remote="${2:-${GIT_REMOTE_GITHUB_NAME}}"

	git checkout -f "${branch}" || git checkout -b "${branch}" "${remote}/${branch}"
}

git_clean() {
	# no need to remove .gitignored files, should be handle by git and we might
	# need these files (.config, scripts, etc.)
	git clean -fd
}

# [ $1: ref, default: HEAD ]
git_get_sha() {
	git rev-parse "${1:-HEAD}"
}

git_get_current_branch() {
	git rev-parse --abbrev-ref HEAD
}

tg_get_first() {
	tg info --series | head -n1 | awk '{ print $1 }'
}

# [ $1: branch, default: current branch ]
is_tg_top() {
	[ "${1:-$(git_get_current_branch)}" = "${TG_TOPIC_TOP}" ]
}

# $1: branch
skipped_tg_topic() {
	[ "${TG_TOPIC_SKIP}" = "${1}" ]
}


###############
## TG Update ##
###############

tg_update_base() { local sha_before_update
	git_checkout "${TG_TOPIC_BASE}"

	if [ "${UPD_TG_NOT_BASE}" = 1 ]; then
		git pull --ff-only "${GIT_REMOTE_GITHUB_NAME}" \
			"${TG_TOPIC_BASE}"
		return 0
	fi

	sha_before_update=$(git_get_sha HEAD)

	# this branch has to be in sync with upstream, no merge
	git pull --ff-only "${GIT_REMOTE_NET_NEXT_URL}" "${GIT_REMOTE_NET_NEXT_BRANCH}"
	if [ "${UPD_TG_FORCE_SYNC}" != 1 ] && \
	   [ "${sha_before_update}" = "$(git_get_sha HEAD)" ]; then
		echo "Already sync with ${GIT_REMOTE_NET_NEXT_URL} (${sha_before_update})"
		exit 0
	fi

	# Push will be done with the 'tg push'
	# in case of conflicts, the resolver will be able to sync the tree to
	# the latest valid state, update the base manually then resolve the
	# conflicts only once
}

tg_update() { local rc=0
	tg update || rc="${?}"

	if [ "${rc}" != 0 ]; then
		# display useful info in the log for the notifications
		git --no-pager diff || true

		tg update --abort
	fi

	return "${rc}"
}

tg_update_tree() {
	git_checkout "${TG_TOPIC_TOP}"

	git fetch "${GIT_REMOTE_GITHUB_NAME}"

	# force to add TG refs in refs/top-bases/, errit is configured for a
	# use with these refs and here below, we also use them.
	git config --local topgit.top-bases refs

	# fetch and update-ref will be done
	tg remote "${GIT_REMOTE_GITHUB_NAME}" --populate

	# do that twice (if there is no error) just in case the base and the
	# rest of the tree were not sync. It can happen if the tree has been
	# updated by someone else and after, the base (only) has been updated.
	# At the beginning of this script, we force an update of the base.
	tg_update
	tg_update
}

tg_get_all_topics() {
	git for-each-ref --format="%(refname)" "refs/remotes/${GIT_REMOTE_GITHUB_NAME}/top-bases/" | \
		sed -e "s#refs/remotes/${GIT_REMOTE_GITHUB_NAME}/top-bases/\\(.*\\)#\\1#g"
}

tg_reset() { local topic
	for topic in $(tg_get_all_topics); do
		git update-ref "refs/top-bases/${topic}" \
			"refs/remotes/${GIT_REMOTE_GITHUB_NAME}/top-bases/${topic}"
		git update-ref "refs/heads/${topic}" "refs/remotes/${GIT_REMOTE_GITHUB_NAME}/${topic}"
	done
	# the base should be already up to date anyway.
	git update-ref "refs/heads/${TG_TOPIC_BASE}" "refs/remotes/${GIT_REMOTE_GITHUB_NAME}/${TG_TOPIC_BASE}"
}

# $1: last return code
tg_trap_reset() { local rc
	rc="${1}"

	# print the error message is any.
	if print_err "${rc}"; then
		return 0
	fi

	tg_reset

	return "${rc}"
}


################
## Validation ##
################

# $*: parameters for defconfig
generate_config_no_mptcp() {
	make defconfig "${@}"

	# no need to compile some drivers for our tests
	echo | scripts/config \
		--disable DRM \
		--disable PCCARD \
		--disable ATA \
		--disable MD \
		--disable PPS \
		--disable SOUND \
		--disable USB \
		--disable IOMMU_SUPPORT \
		--disable INPUT_LEDS \
		--disable AGP \
		--disable VGA_ARB \
		--disable EFI \
		--disable WLAN \
		--disable WIRELESS \
		--disable LOGO \
		--disable NFS_FS \
		--disable XFRM_USER \
		--disable INET6_AH \
		--disable INET6_ESP \
		--disable NETDEVICES
}

# $*: parameters for defconfig
generate_config_mptcp() {
	generate_config_no_mptcp "${@}"

	# to avoid warnings/errors, enable KUnit without the extras
	echo | scripts/config -e KUNIT -d KUNIT_DEBUGFS \
	                      -d KUNIT_TEST -d KUNIT_EXAMPLE_TEST \
	                      -d EXT4_KUNIT_TESTS -d SYSCTL_KUNIT_TEST \
	                      -d LIST_KUNIT_TEST -d LINEAR_RANGES_TEST \
	                      -d KUNIT_ALL_TESTS

	echo | scripts/config -e MPTCP -e MPTCP_IPV6 -e MPTCP_KUNIT_TESTS

	# Here, we want to have a failure if some new MPTCP options are
	# available not to forget to enable them. We then don't want to run
	# 'make olddefconfig' which will silently disable these new options.
}

generate_config_i386_mptcp() {
	generate_config_mptcp "KBUILD_DEFCONFIG=i386_defconfig"
}

# $*: config description
compile_kernel() {
	if ! KCFLAGS="-Werror" make -j"$(nproc)" -l"$(nproc)"; then
		err "Unable to compile ${*}"
		return 1
	fi
}

check_compilation_i386() {
	generate_config_i386_mptcp
	compile_kernel "with i386 and CONFIG_MPTCP"
}

check_compilation_no_ipv6() {
	generate_config_mptcp
	echo | scripts/config -d IPV6 -d MPTCP_IPV6
	compile_kernel "without IPv6 and with CONFIG_MPTCP"
}

check_compilation_mptcp_extra_warnings() { local src obj
	for src in net/mptcp/*.c; do
		obj="${src/%.c/.o}"
		touch "${src}"
		KCFLAGS="-Werror" make W=1 "${obj}" || return 1
	done
}

# $1: branch
tg_has_non_mptcp_modified_files() {
	git diff --name-only "refs/top-bases/${1}..refs/heads/${1}" | \
		grep -qEv "^(\.top(deps|msg)$|net/mptcp/)"
}

# $1: branch
check_compilation() { local branch
	branch="${1}"

	# no need to compile without MPTCP if we only changed files in net/mptcp
	if is_tg_top "${branch}" || \
	   tg_has_non_mptcp_modified_files "${branch}"; then
		generate_config_no_mptcp
		if ! compile_kernel "without CONFIG_MPTCP"; then
			err "Unable to compile without CONFIG_MPTCP"
			return 1
		fi
	fi

	# no need to compile with MPTCP if the option is not available
	if [ -f "net/mptcp/Kconfig" ]; then
		generate_config_mptcp
		if ! compile_kernel "with CONFIG_MPTCP"; then
			err "Unable to compile with CONFIG_MPTCP"
			return 1
		fi

		if ! check_compilation_mptcp_extra_warnings; then
			err "Unable to compile mptcp source code with W=1"
			return 1
		fi

	fi
}

validation() { local curr_branch
	if [ "${UPD_TG_VALIDATE_EACH_TOPIC}" = "1" ]; then
		git_checkout "$(tg_get_first)"

		while true; do
			curr_branch="$(git_get_current_branch)"

			if skipped_tg_topic "${curr_branch}"; then
				echo "We can skip this topic"
			elif ! check_compilation "${curr_branch}"; then
				err "Unable to compile topic ${curr_branch}"
				return 1
			fi

			# switch to the next topic, if any, and show which one
			tg next 2>/dev/null || break
			tg checkout next 2>/dev/null || break
		done

		if ! is_tg_top "${curr_branch}"; then
			err "Not at the top after validation: ${curr_branch}"
			return 1
		fi

		if ! check_compilation_no_ipv6; then
			err "Unable to compile without IPv6"
			return 1
		fi

		if ! check_compilation_i386; then
			err "Unable to compile for i386 arch"
			return 1
		fi
	else
		git_checkout "${TG_TOPIC_TOP}"
		if ! check_compilation "${TG_TOPIC_TOP}"; then
			err "Unable to compile the new version"
			return 1
		fi
	fi
}


############
## TG End ##
############

tg_push_tree() {
	git_checkout "${TG_TOPIC_TOP}"

	tg push -r "${GIT_REMOTE_GITHUB_NAME}"
}

tg_export() { local current_date tag
	git_checkout "${TG_TOPIC_TOP}"

	current_date=$(date +%Y%m%dT%H%M%S)
	tag="${TG_EXPORT_BRANCH}/${current_date}"

	tg export --linearize --force "${TG_EXPORT_BRANCH}"

	# change the committer for the last commit to let Intel's kbuild starting tests
	GIT_COMMITTER_NAME="Matthieu Baerts" \
		GIT_COMMITTER_EMAIL="matthieu.baerts@tessares.net" \
		git commit --amend --no-edit

	git push --force "${GIT_REMOTE_GITHUB_NAME}" "${TG_EXPORT_BRANCH}"

	# send a tag to Github to keep previous commits: we might have refs to them
	git tag "${tag}" "${TG_EXPORT_BRANCH}"
	git push "${GIT_REMOTE_GITHUB_NAME}" "${tag}"
}

tg_for_review() { local tg_conflict_files
	git_checkout "${TG_FOR_REVIEW_BRANCH}"

	git pull "${GIT_REMOTE_GITHUB_NAME}" "${TG_FOR_REVIEW_BRANCH}"

	if ! git merge --no-edit --signoff "${TG_TOPIC_TOP}"; then
		# the only possible conflict would be with the topgit files, manage this
		tg_conflict_files=$(git status --porcelain | grep -E "^DU\\s.top(deps|msg)$")
		if [ -n "${tg_conflict_files}" ]; then
			echo "${tg_conflict_files}" | awk '{ print $2 }' | xargs git rm
			if ! git commit -s --no-edit; then
				err "Unexpected other conflicts: ${tg_conflict_files}"
				return 1
			fi
		else
			err "Unexpected conflicts when updating ${TG_FOR_REVIEW_BRANCH}"
			return 1
		fi
	fi

	git push "${GIT_REMOTE_GITHUB_NAME}" "${TG_FOR_REVIEW_BRANCH}"
}


##########
## Main ##
##########


trap 'print_err "${?}"' EXIT

ERR_MSG="Unable to clean the environment"
git_clean

ERR_MSG="Unable to update the topgit base"
tg_update_base

trap 'tg_trap_reset "${?}"' EXIT

ERR_MSG="Unable to update the topgit tree"
tg_update_tree

ERR_MSG="Unexpected error during the validation phase"
validation

ERR_MSG="Unable to push the update of the Topgit tree"
tg_push_tree

ERR_MSG="Unable to export the TopGit tree"
tg_export

ERR_MSG="Unable to update the ${TG_FOR_REVIEW_BRANCH} branch"
tg_for_review
