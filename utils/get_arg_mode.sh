#!/bin/bash -ex

SERIES="${SERIES:-1}"

# $1: type; $2: ID
is_pw() { local mode id
	mode="${1}"
	id="${2}"
	shift 2

	[[ "${id}" =~ ^[0-9]+$ ]] || return ${?}

	git-pw "${mode}" list --limit 250 -c ID -f simple "${@}" | grep -q "^${id}$"
}

if [ -f "${1}" ]; then
	echo "files"
elif [ "${1}" = "patch" ] || [ "${1}" = "series" ]; then
	echo "${1}"
elif [ "${SERIES}" = 1 ] && is_pw series "${1}"; then
	echo "series"
elif is_pw patch "${1}" \
		 --state "new" \
		 --state "under-review" \
		 --state "queued" \
		 --state "mainlined" \
		 --state "handled-elsewhere" \
		 --state "deferred"; then
	echo "patch"
else
	echo "'${1}': Not a file nor a patchwork ref" >&2
	exit 1
fi
