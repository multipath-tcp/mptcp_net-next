#!/bin/bash -e

[ -f "${1}" ] || [ -d "${1}" ]
PATCH="${1}"
shift

DRY_RUN=""
[ "${GO}" != 1 ] && DRY_RUN="--dry-run"

SE_ID="${SE_ID:-linux}"

# https://www.marcusfolkesson.se/blog/get_maintainers-and-git-send-email/
add_config() {
	local key="sendemail.${SE_ID}.${1}"
	if [ -z "$(git config "${key}")" ]; then
		git config "${key}" "${2}"
	fi
}
add_config "tocmd" "\`pwd\`/.get_maintainer.sh --nogit --nogit-fallback --norolestats --nol"
add_config "cccmd" "\`pwd\`/.get_maintainer.sh --nogit --nogit-fallback --norolestats --nom"

git send-email ${DRY_RUN} --identity="${SE_ID}" --annotate "${@}" "${PATCH}"

if [ "${GO}" != 1 ]; then echo "Use GO=1 to actually send it"; fi
