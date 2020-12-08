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
