#! /bin/bash -ex

[ -f "${1}" ]

TOP="t/upstream"
TG_TOP=${TG_TOP:-${TOP}}

# the last commit is always a DO-NOT-MERGE one.
if [ "${TG_TOP}" = "${TOP}" ]; then
	TG_TOP_NEXT=$(git show "${TG_TOP}:.topdeps")
	while git show "${TG_TOP_NEXT}:.topmsg" | grep "^Subject: " | grep -q "DO-NOT-MERGE"; do
		TG_TOP="${TG_TOP_NEXT}"
		TG_TOP_NEXT=$(git show "${TG_TOP}:.topdeps")
	done
fi

echo "Adding new patch before ${TG_TOP}"

git checkout "${TG_TOP}"
[ -f .topdeps ]

PARENT="$(cat .topdeps)"
git checkout "${PARENT}"
git branch -f tmp
git checkout tmp
git am -3 "${@}" || { echo "ERROR with git am. Please fix in another" \
                           "terminal (up to 'git am --continue') and press" \
                           "enter to continue"; read; }
git checkout "${PARENT}"
tg import "${PARENT}"..tmp
BRANCH=$(git rev-parse --abbrev-ref HEAD)
git checkout "${TG_TOP}"
echo ${BRANCH} > .topdeps
git commit -sm "tg: switch to ${BRANCH}" .topdeps
tg update
git checkout ${TOP}
tg update
echo "push?"
read
tg push
for PATCH in "${@}"; do
	./.patch-file-accept.sh "${PATCH}"
done
