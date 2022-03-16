#!/bin/bash

COLOR_RED="\E[1;31m"
COLOR_GREEN="\E[1;32m"
COLOR_BLUE="\E[1;34m"
COLOR_RESET="\E(B\E[m"

export TG_BASE_NET_NEXT="net-next"
export TG_BASE_NET="net"
export TG_TOPIC_TOP_NET_NEXT="t/upstream"
export TG_TOPIC_TOP_NET="${TG_TOPIC_TOP_NET_NEXT}-net"
export TG_FOR_REVIEW_NET_NEXT="for-review"
export TG_FOR_REVIEW_NET="${TG_FOR_REVIEW_NET_NEXT}-net"
export TG_EXPORT_NET_NEXT="export"
export TG_EXPORT_NET="${TG_EXPORT_NET_NEXT}-net"

# $1: color, $2: text
print_color() {
	echo -e "${START_PRINT:-}${*}${COLOR_RESET}"
}

print() {
	print_color "${COLOR_GREEN}${*}"
}

printinfo() {
	print_color "${COLOR_BLUE}${*}"
}

printerr() {
	print_color "${COLOR_RED}${*}" >&2
}

topgit_get_remote() {
	if ! git config topgit.remote; then
		printerr "No topgit.remote in the git config, please fix that"
		return 1
	fi
}

check_sha() { local remote top sha_loc sha_rem
	remote="${1}"
	top="${2}"

	sha_loc="$(git rev-parse "${top}")"
	sha_rem="$(git rev-parse "${remote}/${top}")"
	if [ "${sha_loc}" != "${sha_rem}" ]; then
		printerr "You are not sync with the remote ${remote} for ${top}, please fix that"
		return 1
	fi
}

check_sync_upstream() { local remote sha_loc sha_rem
	# only if you know what you are doing :)
	# e.g. you include squash-to patch and new patches
	if [ "${TG_SKIP_CHECK_SYNC:-}" = "1" ]; then
		printinfo "Check sync upstream has been skipped."
		return 0
	fi

	remote="$(topgit_get_remote)" || return 1
	git fetch "${remote}"

	check_sha "${remote}" "${TG_TOPIC_TOP_NET_NEXT}" || return 1
	check_sha "${remote}" "${TG_TOPIC_TOP_NET}" || return 1

	return 0
}

# Trap to display a message when there is an error (set -e)
# Src: http://stackoverflow.com/a/185900
# Available variables: https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html
trap_error() {
	local cmd="${BASH_COMMAND}"
	# to keep the last commands from the error and not these, disable 'set -x'
	if [[ $- =~ x ]]; then
		set +x
		local had_set_x=1
	else
		local had_set_x=0
	fi

	local parent_lineno="${1}"
	local message="${2}"
	local code="${3:-1}"
	if [[ -n "${message}" ]] ; then
		printerr "${message}"
	else
		printerr "Error when launching" \
		         "'${CURRENT_SCRIPT[*]} ${BASH_ARGV[*]}' on or near" \
		         "line ${parent_lineno} when calling '${cmd}':"
		local i
		for (( i=0; i<${#BASH_SOURCE[@]}; i++ )); do
			printerr " - ${BASH_SOURCE[${i}]}:${FUNCNAME[${i}]}:${BASH_LINENO[${i}-1]}"
		done
	fi

	printerr "\nThe command '${cmd}' has failed with error ${code}"

	# if with 'set -e', exit with the right rc
	if [[ $- =~ e ]]; then
		exit "${code}"
	fi
	if [ -n "${had_set_x}" ]; then
		set -x
	fi
}

# trap to understand where we had an issue but only with 'set -e'
if [[ $- =~ e ]]; then
	trap 'trap_error ${LINENO}' ERR
fi

if [ "${DEBUG:-}" == "1" ]; then
	set -x
fi
