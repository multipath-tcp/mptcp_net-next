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
TG_TOPIC_BASE_SHA_ORIG="${TG_TOPIC_BASE}" # will become a sha later
TG_TOPIC_TOP="t/upstream"
TG_TOPICS_SKIP=("t/DO-NOT-MERGE-mptcp-enabled-by-default"
		"t/mptcp-remove-multi-addresses-and-subflows-in-PM")
TG_EXPORT_BRANCH="export"
TG_FOR_REVIEW_BRANCH="for-review"

ERR_MSG=""
TG_PUSH_NEEDED=0

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

topic_has_been_upstreamed() { local subject="${1}"
	git log \
		--fixed-strings \
		--grep "${subject}" \
		--format="format:==%s==" \
		"${TG_TOPIC_BASE_SHA_ORIG}..${TG_TOPIC_BASE}" | \
			grep -q --fixed-strings "==${subject}=="
}

tg_get_first() {
	tg info --series | head -n1 | awk '{ print $1 }'
}

# [ $1: branch, default: current branch ]
is_tg_top() {
	[ "${1:-$(git_get_current_branch)}" = "${TG_TOPIC_TOP}" ]
}

# $1: branch
skipped_tg_topic() { local topic curr
	curr="${1}"

	for topic in "${TG_TOPICS_SKIP[@]}"; do
		if [ "${topic}" = "${curr}" ]; then
			return 0
		fi
	done
	return 1
}

empty_tg_topic() {
	[ "$(tg patch | grep -c "diff --git a/")" = "0" ]
}


###############
## TG Update ##
###############

tg_update_base() {
	git_checkout "${TG_TOPIC_BASE}"

	if [ "${UPD_TG_NOT_BASE}" = 1 ]; then
		git pull --ff-only "${GIT_REMOTE_GITHUB_NAME}" \
			"${TG_TOPIC_BASE}"
		return 0
	fi

	TG_TOPIC_BASE_SHA_ORIG=$(git_get_sha HEAD)

	# this branch has to be in sync with upstream, no merge
	git pull --ff-only "${GIT_REMOTE_NET_NEXT_URL}" "${GIT_REMOTE_NET_NEXT_BRANCH}"
	if [ "${UPD_TG_FORCE_SYNC}" != 1 ] && \
	   [ "${TG_TOPIC_BASE_SHA_ORIG}" = "$(git_get_sha HEAD)" ]; then
		echo "Already sync with ${GIT_REMOTE_NET_NEXT_URL} (${TG_TOPIC_BASE_SHA_ORIG})"
		exit 0
	fi

	# Push will be done with the 'tg push'
	# in case of conflicts, the resolver will be able to sync the tree to
	# the latest valid state, update the base manually then resolve the
	# conflicts only once
	TG_PUSH_NEEDED=1
}

tg_update_abort_exit() {
	ERR_MSG+=": $(git_get_current_branch)"

	tg update --abort

	exit 1
}

tg_update_resolve_or_exit() { local subject
	subject=$(grep "^Subject: " .topmsg | cut -d\] -f2- | sed "s/^ //")

	if ! topic_has_been_upstreamed "${subject}"; then
		# display useful info in the log for the notifications
		git --no-pager diff || true

		tg_update_abort_exit
	fi

	echo "The commit '${subject}' has been upstreamed, trying auto-fix:"

	git checkout --theirs .
	git add -u
	git commit -s --no-edit

	if [ -n "$(tg files)" ]; then
		echo "This topic was supposed to be empty because the commit " \
		     "seems to have been sent upstream: abording."

		# display useful info in the log for the notifications
		tg patch || true

		tg_update_abort_exit
	fi
}

tg_update() {
	if ! tg update; then
		tg_update_resolve_or_exit

		while ! tg update --continue; do
			tg_update_resolve_or_exit
		done
	fi
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
	echo | scripts/config -e KUNIT -d KUNIT_ALL_TESTS \
	                      -d LINEAR_RANGES_TEST -d BITS_TEST

	# For INET_MPTCP_DIAG
	echo | scripts/config -e INET_DIAG \
	                      -d INET_UDP_DIAG -d INET_RAW_DIAG -d INET_DIAG_DESTROY

	echo | scripts/config -e MPTCP -e IPV6 -e MPTCP_IPV6 -e MPTCP_KUNIT_TEST

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

# $1: src file ; $2: warn line
check_sparse_output() { local src warn unlock_sock_fast
	src="${1}"
	warn="${2}"

	if [ -z "${warn}" ]; then
		return 0
	fi

	# ignore 'notes', only interested in the error message
	if [ "$(echo "${warn}" | \
		grep -cE "^${src}: note: in included file")" -eq 1 ]; then
		return 0
	fi

	for unlock_sock_fast in $(git grep -p unlock_sock_fast -- "${src}" | \
					grep "${src}=" | \
					sed "s/.*\b\(\S\+\)(.*/\1/g"); do
		# ./include/net/sock.h:1608:31: warning: context imbalance in 'mptcp_close' - unexpected unlock
		if [ "$(echo "${warn}" | \
			grep -cE "./include/net/sock.h:[0-9]+:[0-9]+: warning: context imbalance in '${unlock_sock_fast}' - unexpected unlock")" -eq 1 ]; then
			echo "Ignore the following warning because unlock_sock_fast() conditionally releases the socket lock: '${warn}'"
			return 0
		fi
	done

	case "${src}" in
		"net/mptcp/protocol.c")
			# net/mptcp/protocol.c:1535:24: warning: context imbalance in 'mptcp_sk_clone' - unexpected unlock
			if [ "$(echo "${warn}" | grep -cE "net/mptcp/protocol.c:[0-9]+:[0-9]+: warning: context imbalance in 'mptcp_sk_clone' - unexpected unlock")" -eq 1 ]; then
				echo "Ignore the following warning because sk_clone_lock() conditionally acquires the socket lock, (if return value != 0), so we can't annotate the caller as 'release': ${warn}"
				return 0
			fi
		;;
	esac

	echo "Non whitelisted warning: ${warn}"
	return 1
}

check_compilation_mptcp_extra_warnings() { local src obj warn
	for src in net/mptcp/*.c; do
		obj="${src/%.c/.o}"
		if [[ "${src}" = *"_test.mod.c" ]]; then
			continue
		fi

		touch "${src}"
		KCFLAGS="-Werror" make W=1 "${obj}" || return 1

		touch "${src}"
		# RC is not >0 if warn but warn are lines not starting with spaces
		while read -r warn; do
			check_sparse_output "${src}" "${warn}" || return 1
		done <<< "$(make C=1 "${obj}" 2>&1 >/dev/null | grep "^\S")"
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

	generate_config_mptcp
	if ! compile_kernel "with CONFIG_MPTCP"; then
		err "Unable to compile with CONFIG_MPTCP"
		return 1
	fi

	if ! check_compilation_mptcp_extra_warnings; then
		err "Unable to compile mptcp source code with W=1 C=1"
		return 1
	fi
}

validation() { local curr_branch
	if [ "${UPD_TG_VALIDATE_EACH_TOPIC}" = "1" ]; then
		git_checkout "$(tg_get_first)"

		while true; do
			curr_branch="$(git_get_current_branch)"

			if skipped_tg_topic "${curr_branch}"; then
				echo "We can skip this topic"
			elif ! is_tg_top "${curr_branch}" && empty_tg_topic; then
				echo "We can skip empty topic";
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
	if [ "${TG_PUSH_NEEDED}" = "0" ]; then
		return 0
	fi

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
		GIT_COMMITTER_EMAIL="matttbe@kernel.org" \
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
