#!/bin/bash -e

SUBJECT="${1:?}"

# remote dot at the end if any
[[ "${SUBJECT}" =~ "."$ ]] && SUBJECT="${SUBJECT:0:-1}"

COMMIT="${2}"
DELEGATE="matttbe"

get_ids() {
	git-pw patch list --limit 250 --sort date --format simple -c ID \
		--state new \
		--state under-review \
		--state rfc \
		--state changes-requested \
		--state awaiting-upstream \
		--state queued \
		--state needs-ack \
		"${SUBJECT}" |
			tail -n+3
}

STATE="accepted"
for i in $(get_ids); do
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
