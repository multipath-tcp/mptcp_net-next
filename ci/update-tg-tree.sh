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

# topgit utilitary
TG_SETUP_URL="https://github.com/mackyle/topgit/releases/download/topgit-0.19.12/topgit-0.19.12.tar.gz"
TG_SETUP_SHA256="8b6b89c55108cc75d007f63818e43aa91b69424b5b8384c06ba2aa3122f5e440"
TG_SETUP_PREFIX="build"

# Local repo
TG_TOPIC_BASE="net-next"
TG_TOPIC_TOP="t/upstream"
TG_EXPORT_BRANCH="export"


###########
## Utils ##
###########

# $@: message to display before quiting
exit_err() {
	echo "ERROR: ${*}"
	exit 1
}

# $1: branch ;  [ $2: remote, default: origin ]
git_checkout() { local branch remote
	branch="${1}"
	remote="${2:-${GIT_REMOTE_GERRITHUB_NAME}}"

	git checkout -f "${branch}" || git checkout -b "${branch}" "${remote}/${branch}"
}

git_clean() {
	# no need to remove .gitignored files, should be handle by git and we might
	# need these files (.config, scripts, etc.)
	git clean -fd
}


##############
## TG Setup ##
##############

# $1: output file
tg_setup_download_if_needed() { local sha_check
	sha_check="topgit.check"

	# if already downloaded
	printf "%s  %s\\n" "${TG_SETUP_SHA256}" "${output}" > "${sha_check}"
	[ -f "topgit.tar.gz" ] && sha256 -c --quiet "${sha_check}" && return 0

	curl -L "${TG_SETUP_URL}" -o "${output}"
}

tg_setup_install() { local output
	output="topgit.tar.gz"

	tg_setup_download_if_needed "${output}"

	rm -rf "topgit-"* "./${TG_SETUP_PREFIX}" 2>/dev/null
	mkdir -p "./${TG_SETUP_PREFIX}"

	tar xzf "${output}"
	cd "topgit-"*
	# it seems a full path is needed for the prefix
	make prefix="$(realpath "../${TG_SETUP_PREFIX}")" install
	cd ..

	PATH="${PWD}/${TG_SETUP_PREFIX}/bin:${PATH}"
}

tg_setup() {
	# use 'patches' as a build dir as it is ignored by git and not used by make
	mkdir -p patches/topgit && cd "${_}"

	tg_setup_install

	cd ../..
}


###############
## TG Update ##
###############

tg_update_base() {
	git_checkout "${TG_TOPIC_BASE}"

	# this branch has to be in sync with upstream, no merge
	git pull --ff-only "${GIT_REMOTE_NET_NEXT_URL}" "${GIT_REMOTE_NET_NEXT_BRANCH}"
	git push "${GIT_REMOTE_GERRITHUB_NAME}" "${TG_TOPIC_BASE}"
}

tg_update() { local rc=0
	tg update || rc="${?}"

	if [ "${rc}" != 0 ]; then
		tg update --abort
	fi

	return "${rc}"
}

tg_update_tree() {
	git_checkout "${TG_TOPIC_TOP}"

	git fetch "${GIT_REMOTE_GERRITHUB_NAME}"
	tg remote "${GIT_REMOTE_GERRITHUB_NAME}" --populate

	tg_update
}

tg_get_all_topics() {
	git for-each-ref --format="%(refname)" "refs/remotes/${GIT_REMOTE_GERRITHUB_NAME}/top-bases/" | \
		sed -e "s#refs/remotes/${GIT_REMOTE_GERRITHUB_NAME}/top-bases/\\(.*\\)#\\1#g"
}

tg_reset() { local topic
	for topic in $(tg_get_all_topics); do
		git update-ref "refs/top-bases/${topic}" \
			"refs/remotes/${GIT_REMOTE_GERRITHUB_NAME}/top-bases/${topic}"
		git update-ref "refs/heads/${topic}" "refs/remotes/${GIT_REMOTE_GERRITHUB_NAME}/${topic}"
	done
	# the base should be already up to date anyway.
	git update-ref "refs/heads/${TG_TOPIC_BASE}" "refs/remotes/${GIT_REMOTE_GERRITHUB_NAME}/${TG_TOPIC_BASE}"
}

# $1: last return code
tg_trap_reset() { local rc
	rc="${1}"

	# check return code: if different than 0, we exit with an error: reset
	[ "${rc}" -eq 0 ] && return 0

	tg_reset

	exit "${rc}"
}


################
## Validation ##
################

generate_config() {
	make defconfig

	cat <<EOF >> .config
CONFIG_MPTCP=y
EOF
}

check_compilation() {
	generate_config
	make -j"$(nproc)" -l"$(nproc)"
}

validation() {
	check_compilation || exit_err "Unable to compile the new version"
}


############
## TG End ##
############

tg_push_tree() {
	git_checkout "${TG_TOPIC_TOP}"

	tg push -r "${GIT_REMOTE_GERRITHUB_NAME}"
}

tg_export() {
	git_checkout "${TG_TOPIC_TOP}"

	tg export --linearize --force "${TG_EXPORT_BRANCH}"
	git push --force "${GIT_REMOTE_GERRITHUB_NAME}" "${TG_EXPORT_BRANCH}"
}


##########
## Main ##
##########

git_clean || exit_err "Unable to clean the environment"
tg_setup || exit_err "Unable to setup topgit"
tg_update_base || exit_err "Unable to update the topgit base"
trap 'tg_trap_reset "${?}"' EXIT
tg_update_tree || exit_err "Unable to update the topgit tree"
validation || exit_err "Unexpected error during the validation phase"
tg_push_tree || exit_err "Unable to push the update of the Topgit tree"
tg_export || exit_err "Unable to export the TopGit tree"
