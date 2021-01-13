#! /bin/bash -ex

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

TOP="t/upstream"
TG_TOP=${TG_TOP:-${TOP}}

MODE=$(bash "-${-}" ./.get_arg_mode.sh "${1}")

apply_patches_files() {
	if ! git am -3 "${@}"; then
		printerr "ERROR with git am. Please fix in another terminal" \
		         "(up to 'git am --continue' included) and press ENTER" \
		         "to continue."
		read -r
	fi
}

apply_patches_git_pw() {
	for i in "${@}"; do
		if ! git-pw "${MODE}" apply ${GIT_PW_ARG:+"${GIT_PW_ARG}"} "${i}"; then
			printerr "ERROR with 'git-pw ${MODE} apply ${i}'. " \
			         "Please fix in another terminal and press" \
			         "ENTER to continue."
			read -r
		fi
	done
}

apply_patches_series() {
	GIT_PW_ARG="" apply_patches_git_pw "${@}"
}

apply_patches_patch() {
	GIT_PW_ARG="--no-deps" apply_patches_git_pw "${@}"
}

apply_patches() {
	"apply_patches_${MODE}" "${@}"
}

print_rebase_pause() {
	print "${1}\n" \
	      "Use 'git rebase -i \"${2}\"' to fix anything if needed.\n" \
	      "Press Enter to continue."
	read -r
}

# $1: git base; $2: git end
checkpatch() {
	if ! ./.checkpatch.sh --git "${1}..${2}"; then
		print_rebase_pause "Error with checkpatch." "${1}"
	fi
}

# $1: ref
commit_desc() {
	git log -1 --format="%h %s" "${1}"
}

# $1: git base; $2: git end
check_commit_msgs() { local commit sob=0 dot=0
	for commit in $(git log --format="%H" "${1}..${2}"); do
		if ! git log -1 --format="%b" "${commit}" | \
		     sed "/^$/d" | \
		     tail -n1 | \
		     grep -q "^Signed-off-by: "; then
			printinfo "Please fix the SOB of:" \
			          "$(commit_desc "${commit}")"
			sob=1
		fi

		if git log -1 --format="%s" "${commit}" | grep -q "\.$"; then
			printinfo "Please remove the dot at the end of:" \
			          "$(commit_desc "${commit}")"
			dot=1
		fi
	done
	if [ "${sob}" != 0 ]; then
		print_rebase_pause "Please make sure the Signed-off-by is the last line." "${1}"
	fi
	if [ "${dot}" != 0 ]; then
		print_rebase_pause "Please make sure no commit have a dot at the end of the commit title." "${1}"
	fi
}

accept_patches() { local commit subject
	while read -r commit subject; do
		./.patch-subject-accept.sh "${subject}" "${commit}"
	done <<< "$(git log --reverse --format="%H %s" "${1}" | grep -v "^\S\+ tg ")"
}


# the last commit is always a DO-NOT-MERGE one.
if [ "${TG_TOP}" = "${TOP}" ]; then
	TG_TOP_NEXT=$(git show "${TG_TOP}:.topdeps")
	while git show "${TG_TOP_NEXT}:.topmsg" | grep "^Subject: " | grep -q "DO-NOT-MERGE"; do
		TG_TOP="${TG_TOP_NEXT}"
		TG_TOP_NEXT=$(git show "${TG_TOP}:.topdeps")
	done
fi

printinfo "Adding new patch(es) before ${TG_TOP}"

git checkout "${TG_TOP}"
[ -f .topdeps ]

# Apply patches in a tmp branch created from the parent commit of TG_TOP
PARENT="$(cat .topdeps)"
git checkout "${PARENT}"
git branch -f tmp
git checkout tmp
apply_patches "${@}"

# Make sure all patches are OK
checkpatch "${PARENT}" "tmp"

# Make sure all patches are ending with Signed-off-by
check_commit_msgs "${PARENT}" "tmp"

# Other checks?
print_rebase_pause "No additional tags to add?" "${PARENT}"

# Import new patches with tg import
git checkout "${PARENT}"
tg import "${PARENT}"..tmp

# Change the dep of TG_TOP to point to the last new patch
BRANCH=$(git rev-parse --abbrev-ref HEAD)
git checkout "${TG_TOP}"
echo "${BRANCH}" > .topdeps
git commit -sm "tg: switch to ${BRANCH}" .topdeps
TG_PUSH=0 TG_TOP="${TG_TOP}" ./.publish.sh

# update the tree
TG_PUSH=1 TG_TOP="${TOP}" ./.publish.sh

# Mark as done
accept_patches "${PARENT}..${BRANCH}"
