#!/bin/bash -e

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

PATCH="${1}"

BRANCH=$(git rev-parse --abbrev-ref HEAD)
printinfo "Current branch is: ${BRANCH}"
head -n2 .topmsg | grep "^Subject: "

if [ "${BRANCH}" = "t/upstream" ] || [ ! -f ".topdeps" ]; then
	printerr "wrong branch... exit"
	exit 1
fi

MODE=$(SERIES=0 bash "-${-}" ./.get_arg_mode.sh "${PATCH}")

TMP_FILE=""

exit_trap() {
	if [ -n "${TMP_FILE}" ]; then
		rm -f "${TMP_FILE}"
	fi
}

am_files() { local nb subject sha
	if git am -3 -s "${1}" || { git am --abort && git am -s "${1}"; }; then
		subject="$(grep "^Subject: " "${1}" | head -n1)"
		if echo "${subject}" | grep -q "\[PATCH.* [0-9]\+/[0-9]\+\] "; then
			# shellcheck disable=SC2001
			nb=" patch $(echo "${subject}" | \
				sed "s#.*\[PATCH.* \([0-9]\+/[0-9]\+\)\].\+#\1#g")"
		fi
		sha=$(git rev-parse HEAD)

		print " - $(git rev-parse --short HEAD): \"squashed\"${nb}" \
		      "in \"$(./.title.sh)\""
		printinfo "trying signed-off"
		./.signed-off.sh

		bash "-${-}" ./.patch-file-accept.sh "${1}" "${sha}"
		exit
	fi


	if [ "$(git status --porcelain | grep -c -v "^?? ")" = "0" ]; then
		printinfo "'git am' didn't do anything, use patch then 'end-squash.sh'"
		unset TMP_FILE

		patch -p1 --merge < "${1}"
		exit 1
	fi
}

am_series() {
	printerr "Are you sure you want to apply a series here?"
	exit 1
}

am_patch() {
	TMP_FILE=$(mktemp)

	git-pw patch download "${1}" "${TMP_FILE}"

	am_files "${TMP_FILE}"
}

trap 'exit_trap' EXIT

"am_${MODE}" "${PATCH}"
