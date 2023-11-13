#! /bin/bash

: "${1:?}"

# shellcheck source=./lib.sh
source ./.lib.sh

FETCH=1 ./.git-has-commit.sh

export FETCH=0 NO_BRANCH_CHECK=1

get_fixes() {
	git log -1 "${1}" | grep "^\s*Fixes: " | awk '{print $2}'
}

get_all() {
	local lvl="${1}"
	local sha="${2}"

	local fix
	for fix in $(get_fixes "${sha}"); do
		v=$(./.git-has-commit.sh "${fix}")
		[ -z "${v}" ] && v=/
		printf '\t%.0s' $(seq "${lvl}")
		printf "=> %-6s  ${COLOR_GREEN}%s${COLOR_RESET}\n" "${v}:" "$(git log -1 --oneline "${fix}")"
		get_all "$((lvl + 1))" "${fix}"
	done
}

while read -r sha desc; do
	printinfo "${sha}: ${desc}"
	get_all 1 "${sha}"
	echo
done <<< "$(git log --reverse --format="%h %s" "${1}")"
