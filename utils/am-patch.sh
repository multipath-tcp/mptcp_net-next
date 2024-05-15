#!/bin/bash -e

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

BRANCH=$(git rev-parse --abbrev-ref HEAD)
printinfo "Current branch is: ${BRANCH}"
head -n2 .topmsg | grep "^Subject: "

if [ "${BRANCH}" = "${TG_TOPIC_TOP_NET_NEXT}" ] ||
   [ "${BRANCH}" = "${TG_TOPIC_TOP_NET}" ] ||
   [ ! -f ".topdeps" ]; then
	printerr "wrong branch... exit"
	exit 1
fi

AM_ARGS=()
if [ "${NO_SOB}" != "1" ]; then
	AM_ARGS+=("-s")
fi

check_sync_upstream || exit 1

MODE=$(SERIES=0 bash "-${-}" ./.get_arg_mode.sh "${1}")

TMP_FILE=""

exit_trap() {
	if [ -n "${TMP_FILE}" ]; then
		rm -f "${TMP_FILE}"
	fi
}

am_files() { local nb subject sha msg
	if git am -3 "${AM_ARGS[@]}" "${1}" || { git am --abort && git am "${AM_ARGS[@]}" "${1}"; }; then
		subject="$(grep "^Subject: " "${1}" | head -n1)"
		if echo "${subject}" | grep -q "\[PATCH.* [0-9]\+/[0-9]\+\] "; then
			# shellcheck disable=SC2001
			nb=" patch $(echo "${subject}" | \
				sed "s#.*\[PATCH.* \([0-9]\+/[0-9]\+\)\].\+#\1#g")"
		fi
		sha=$(git rev-parse HEAD)

		msg="- $(git rev-parse --short HEAD): \"squashed\"${nb} in \"$(./.title.sh)\""
		if [ "${NO_SOB}" != "1" ]; then
			printinfo "trying signed-off"
			if ./.signed-off.sh; then
				msg+=$'\n'
				msg+="- $(git rev-parse --short HEAD): \"Signed-off-by\" + \"Co-developed-by\""
			fi
		fi
		print "${msg}"
		wl-copy <<< "${msg}" 2>/dev/null || true

		bash "-${-}" ./.patch-file-accept.sh "${1}" "${sha}"
		exit
	fi


	if [ "$(git status --porcelain | grep -c -v "^?? ")" = "0" ]; then
		printerr "'git am' failed, please resolve the conflicts, then use './.end-squash.sh'"
		unset TMP_FILE

		patch -p1 --merge < "${1}" || true
		exit 1
	fi
}

am_series() {
	printerr "Are you sure you want to apply a series here?"
	exit 1
}

am_patch() {
	TMP_FILE=$(mktemp)

	if [ "${1}" = "patch" ]; then
		shift
	fi

	git-pw patch download "${@}" "${TMP_FILE}"

	am_files "${TMP_FILE}"
}

am_b4() { local opt
	TMP_FILE=$(mktemp)

	if [ "${1}" = "b4" ]; then
		shift
	fi

	opt=(--prep-3way -o - --cherry-pick _)
	if [ "${NO_SOB}" != "1" ]; then
		opt+=(--add-link)
	fi

	b4 am "${opt[@]}" "${@}" > "${TMP_FILE}"

	am_files "${TMP_FILE}"
}

trap 'exit_trap' EXIT

"am_${MODE}" "${@}"
