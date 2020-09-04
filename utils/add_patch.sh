#! /bin/bash -ex

[ -f "${1}" ]

TOP="t/upstream"
TG_TOP=${TG_TOP:-${TOP}}

tg_up_err() {
	echo "Please fix the conflicts in another terminal." \
	     "End with ./.end-conflict.sh, then press Enter to continue."
	read
}


tg_update() {
	if ! tg update; then
		tg_up_err

		while ! tg update --continue; do
			tg_up_err
		done
	fi
}


# the last commit is always a DO-NOT-MERGE one.
if [ "${TG_TOP}" = "${TOP}" ]; then
	TG_TOP_NEXT=$(git show "${TG_TOP}:.topdeps")
	while git show "${TG_TOP_NEXT}:.topmsg" | grep "^Subject: " | grep -q "DO-NOT-MERGE"; do
		TG_TOP="${TG_TOP_NEXT}"
		TG_TOP_NEXT=$(git show "${TG_TOP}:.topdeps")
	done
fi

echo "Adding new patch before ${TG_TOP}"

for PATCH in "${@}"; do
	echo "Checkpatch on ${PATCH}"
	./.checkpatch.sh "${PATCH}" || { echo "Error with checkpatch. Press" \
					      "enter to continue"; read; }
done

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
tg_update
git checkout ${TOP}
tg_update
tg push
for PATCH in "${@}"; do
	./.patch-file-accept.sh "${PATCH}"
done
