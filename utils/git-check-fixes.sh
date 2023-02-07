#! /bin/bash

: "${1:?}"

# shellcheck source=./lib.sh
source ./.lib.sh

export FETCH=1

while read -r sha desc; do
	printinfo "${sha}: ${desc}"
	printinfo "Fixes:"
	git log -1 "${sha}" | grep "^\s*Fixes: " | awk '{print $2}' | xargs ./.git-has-commit.sh
	FETCH=0
done <<< "$(git log --reverse --format="%h %s" "${1}")"
