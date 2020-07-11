#!/bin/bash -e

SUBJECT="${1}"
[ -n "${SUBJECT}" ]

COMMIT="${2}"
DELEGATE="matttbe"

get_ids() {
	bash "-${-}" ./.patch-subject-get-ids.sh "${1}"
}

STATE="accepted"
for i in $(get_ids "${SUBJECT}"); do
	echo "Set state ${STATE} to patch-id ${i}"
	git-pw patch update \
		--state "${STATE}" \
		${DELEGATE:+--delegate "${DELEGATE}"} \
		${COMMIT:+--commit-ref "${COMMIT}"} \
		"${i}"
	STATE="superseded"
	unset DELEGATE # reviewer might be someone else
done

if [ -z "${i}" ]; then
	echo -e "\n\tWARNING: Patch '${SUBJECT}' was not found in patchwork\n"
fi
