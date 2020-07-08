#!/bin/bash -ex

git_current_branch() {
	git rev-parse --abbrev-ref HEAD
}

tg_empty() {
	[ "$(tg patch | grep -c "diff --git a/")" = "0" ]
}

./.tg-first.sh

while true; do
	BRANCH="$(git_current_branch)"
	if tg_empty && [ "${BRANCH}" != "t/upstream" ]; then
		DEPS="$(cat .topdeps)"
		tg annihilate # it jumps to the next one
		tg update
		echo "${DEPS}" > .topdeps
		git commit -sm "tg: parent topic is empty" .topdeps
		tg update
		tg push "${BRANCH}"
		#tg delete "${BRANCH}"
	else
		tg checkout next || break
		tg update
	fi
done

tg update
tg push
