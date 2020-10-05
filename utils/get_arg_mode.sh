#!/bin/bash

# $1: type; $2: ID
is_pw() {
	[[ "${2}" =~ ^[0-9]+$ ]] || return $?
	git-pw "${1}" list -c ID -f simple | grep -q "^${2}$"
}

if [ -f "${1}" ]; then
	echo "files"
elif is_pw series "${1}"; then
	echo "series"
elif is_pw patch "${1}"; then
	echo "patch"
else
	echo "'${1}': Not a file nor a patchwork ref" >&2
	exit 1
fi
