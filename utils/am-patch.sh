#!/bin/bash

PATCH="${1}"

exit_trap() { local rc
	rc=${1}
	echo -e "\n\n\t ====> Do not forget the signed-off-by"
}

BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "Current branch is: ${BRANCH}"
head -n2 .topmsg | grep "^Subject: "

if [ "${BRANCH}" = "t/upstream" ] || [ ! -f ".topdeps" ]; then
	echo "wrong branch... exit"
	exit 1
fi

if git am -3 -s "${PATCH}"; then
	COMMIT="$(git rev-parse HEAD)"
	echo -e "\n\n\t ====> Patch applied with success: $(git rev-parse --short HEAD)"
	if $(echo "${PATCH}" | grep -q "\[PATCH.\+[0-9]\+_[0-9]\+\]"); then
		NB=" patch $(echo "${PATCH}" | sed "s/.*\[PATCH.*\+ \([0-9]\+\)_\([0-9]\+\)\].*/\1\/\2/g")"
	else
		NB=""
	fi
	printf "\t- %s: \"squashed\"%s in \"%s\"\n" \
		"$(git rev-parse --short HEAD)" \
		"${NB}" \
		"$(./.title.sh)"
	echo -e "\ttrying signed-off\n"
	./.signed-off.sh
	bash ./.patch-file-accept.sh "${PATCH}" "${COMMIT}"
	exit
fi

trap 'exit_trap ${?}' EXIT

if [ "$(git status --porcelain | grep -v "^?? " | wc -l)" = "0" ]; then
	echo "Am didn't do anything, use patch then 'end-squash.sh'"
	patch -p1 --merge < "${PATCH}"
	exit 1
fi
