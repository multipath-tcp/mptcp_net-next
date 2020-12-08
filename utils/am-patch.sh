#!/bin/bash

PATCH="${1}"

BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "Current branch is: ${BRANCH}"
head -n2 .topmsg | grep "^Subject: "

if [ "${BRANCH}" = "t/upstream" ] || [ ! -f ".topdeps" ]; then
	echo "wrong branch... exit"
	exit 1
fi

MODE=$(SERIES=0 bash "-${-}" ./.get_arg_mode.sh "${PATCH}")

exit_trap() {
	echo -e "\n\n\t ====> Do not forget the signed-off-by"
}

am_files() { local nb subject
	if git am -3 -s "${1}" || { git am --abort && git am -s "${1}"; }; then
		subject="$(grep "^Subject: " "${1}" | head -n1)"
		if echo "${subject}" | grep -q "\[PATCH.* [0-9]\+/[0-9]\+\] "; then
			# shellcheck disable=SC2001
			nb=" patch $(echo "${subject}" | \
				sed "s#.*\[PATCH.* \([0-9]\+/[0-9]\+\)\].\+#\1#g")"
		fi

		printf "\n\t- %s: \"squashed\"%s in \"%s\"\n" \
			"$(git rev-parse --short HEAD)" \
			"${nb}" \
			"$(./.title.sh)"
		printf "\ttrying signed-off\n\n"
		./.signed-off.sh

		bash ./.patch-file-accept.sh "${1}" "$(git rev-parse HEAD)"
		exit
	fi

	trap 'exit_trap ${?}' EXIT

	if [ "$(git status --porcelain | grep -c -v "^?? ")" = "0" ]; then
		echo "Am didn't do anything, use patch then 'end-squash.sh'"
		patch -p1 --merge < "${1}"
		exit 1
	fi
}

am_series() {
	echo "Are you sure you want to apply a series here?"
	exit 1
}

am_patch() {
	am_files "$(git-pw patch download "${1}")"
}

"am_${MODE}" "${PATCH}"
