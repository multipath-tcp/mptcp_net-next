#! /bin/bash

set -ex

[ -f "${1}" ]

TOP="t/upstream"
TG_TOP=${TG_TOP:-${TOP}}

# the last commit is always the DO-NOT-MERGE one.
if [ "${TG_TOP}" = "${TOP}" ]; then
	TG_TOP=$(git show "${TG_TOP}:.topdeps")
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
