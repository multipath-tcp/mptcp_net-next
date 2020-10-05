#! /bin/bash -ex

TOP="t/upstream"
TG_TOP=${TG_TOP:-${TOP}}

# $1: type; $2: ID
is_pw() {
	[[ "${2}" =~ ^[0-9]+$ ]] || return $?
	git-pw "${1}" list -c ID -f simple | grep -q "^${2}$"
}

if [ -f "${1}" ]; then
	MODE="files"
elif is_pw series "${1}"; then
	MODE="series"
elif is_pw patch "${1}"; then
	MODE="patch"
else
	echo "'${1}': Not a file nor a patchwork ref" >&2
	exit 1
fi

apply_patches_files() {
	if ! git am -3 "${@}"; then
		echo "ERROR with git am. Please fix in another terminal (up to" \
		     "'git am --continue' included) and press ENTER to continue."
		read -r
	fi
}

apply_patches_git_pw() {
	for i in "${@}"; do
		if ! git-pw "${MODE}" apply ${GIT_PW_ARG:+"${GIT_PW_ARG}"} "${i}"; then
			echo "ERROR with 'git-pw ${MODE} apply ${i}'. Please" \
			     "resolve in another terminal and press ENTER to" \
			     "continue."
			read -r
		fi
	done
}

apply_patches_series() {
	GIT_PW_ARG="" apply_patches_git_pw "${@}"
}

apply_patches_patch() {
	GIT_PW_ARG="--deps" apply_patches_git_pw "${@}"
}

apply_patches() {
	"apply_patches_${MODE}" "${@}"
}

# $1: git base; $2: git end
checkpatch() {
	if ! ./.checkpatch.sh --git "${1}..${2}"; then
		echo "Error with checkpatch. Use 'git rebase -i \"${1}\"' to" \
		     "fix anything if needed and press Enter to continue."
		read -r
	fi
}

accept_patches() { local subject
	while read -r subject; do
		./.patch-subject-accept.sh "${subject}"
	done <<< "$(git log --format="%s" "${1}")"
}


# the last commit is always a DO-NOT-MERGE one.
if [ "${TG_TOP}" = "${TOP}" ]; then
	TG_TOP_NEXT=$(git show "${TG_TOP}:.topdeps")
	while git show "${TG_TOP_NEXT}:.topmsg" | grep "^Subject: " | grep -q "DO-NOT-MERGE"; do
		TG_TOP="${TG_TOP_NEXT}"
		TG_TOP_NEXT=$(git show "${TG_TOP}:.topdeps")
	done
fi

echo "Adding new patch(es) before ${TG_TOP}"

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
accept_patches "${PARENT}"..tmp
