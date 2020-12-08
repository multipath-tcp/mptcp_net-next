#!/bin/bash

COLOR_RED="\E[1;31m"
COLOR_GREEN="\E[1;32m"
COLOR_BLUE="\E[1;34m"
COLOR_RESET="\E(B\E[m"

# $1: color, $2: text
print_color() {
	echo -e "${START_PRINT:-}${*}${COLOR_RESET}"
}

print() {
	print_color "${COLOR_GREEN}" "${@}"
}

printinfo() {
	print_color "${COLOR_BLUE}" "${@}"
}

printerr() {
	print_color "${COLOR_RED}" "${@}" >&2
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
