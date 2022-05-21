#!/bin/bash -ex

git_current_branch() {
	git rev-parse --abbrev-ref HEAD
}

tg_empty() {
	[ -z "$(tg files)" ]
}

is_dep() {
	git show "${1}:.topdeps" | grep -q "^${2}$"
}

tg_next() { local curr next
	curr="${1}"
	next="$(tg next)"

	if ! is_dep "${next}" "${curr}"; then
		# tg next seems to have issues returning the right one
		next=t/DO-NOT-MERGE-git-markup-net-next
		if ! is_dep "${next}" "${curr}"; then
			>&2 echo -e "\n\n\tError: unable to find next, not $(tg next) for ${curr}\n\n"
			exit 1
		fi
	fi

	echo "${next}"
}

./.tg-first.sh

while true; do
	BRANCH="$(git_current_branch)"
	if tg_empty && ! [[ "${BRANCH}" =~ ^"t/upstream"* ]]; then
		echo -e "\n\t => Remove ${BRANCH}\n"
		DEPS="$(head -n1 .topdeps)"
		NEXT="$(tg_next "${BRANCH}")"

		# the next line comes from tg annihilate and does:
		#    git rm -f .topdeps .topmsg
		git read-tree "$(git merge-base "refs/top-bases/${BRANCH}" "refs/heads/${BRANCH}")^{tree}"
		git commit --no-verify -sm "TopGit branch ${BRANCH} annihilated."

		git checkout "${NEXT}"
		sed -i "1c\\${DEPS}" .topdeps
		git commit -sm "tg: child topic (${BRANCH}) is empty" .topdeps

		tg update
		tg push "${BRANCH}"

		#tg delete "${BRANCH}" # the next 'tg remote --populate' will get it back
	elif [ "${BRANCH}" = "t/DO-NOT-MERGE-git-markup-end-common-net-net-next" ]; then
		echo -e "\n\t => Special case ${BRANCH}: continue on -net tree\n"
		echo 2 | tg checkout next || break
	elif [ "${BRANCH}" = "t/upstream-net" ]; then
		echo -e "\n\t => Net tree done, switch to net-next tree\n"
		git checkout t/DO-NOT-MERGE-git-markup-net-next
	elif [ "${BRANCH}" = "t/upstream" ]; then
		echo -e "\n\t => End\n"
		break
	else
		echo -e "\n\t => Not empty, skip ${BRANCH}\n"
		NEXT="$(tg_next "${BRANCH}")"
		git checkout "${NEXT}" || exit 1
		tg update
	fi
done

echo -e "\n\nPublish or Ctrl+C for manual push?"
read -r
./.publish.sh
