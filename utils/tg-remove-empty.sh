#!/bin/bash -ex

git_current_branch() {
	git rev-parse --abbrev-ref HEAD
}

tg_empty() {
	[ -z "$(tg files)" ]
}

./.tg-first.sh

while true; do
	BRANCH="$(git_current_branch)"
	if tg_empty && ! [[ "${BRANCH}" =~ ^"t/upstream"* ]]; then
		echo -e "\n\t => Remove ${BRANCH}\n"
		DEPS="$(cat .topdeps)"
		tg annihilate # it jumps to the next one
		tg update
		echo "${DEPS}" > .topdeps
		git commit -sm "tg: parent topic is empty" .topdeps
		tg update
		tg push "${BRANCH}"
		#tg delete "${BRANCH}"
	elif [ "${BRANCH}" = "t/DO-NOT-MERGE-git-markup-end-common-net-net-next" ]; then
		echo -e "\n\t => Special case ${BRANCH}\n"
		git checkout t/DO-NOT-MERGE-git-markup-fixes-net-next
	else
		echo -e "\n\t => Skip ${BRANCH}\n"
		tg checkout next || break
		tg update
	fi
done

echo -e "\n\nPublish or Ctrl+C for manual push?"
read -r
./.publish.sh
