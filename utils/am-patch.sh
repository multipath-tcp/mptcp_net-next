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
	echo -e "\n\n\t ====> Patch applied with success: $(git rev-parse --short HEAD)"
	printf "\t- %s: \"squashed\" in \"%s\"\n" \
		"$(git rev-parse --short HEAD)" \
		"$(./.title.sh)"
	echo -e "\ttrying signed-off\n"
	./.signed-off.sh
	exit
fi

trap 'exit_trap ${?}' EXIT

if [ "$(git status --porcelain | grep -v "^?? " | wc -l)" = "0" ]; then
	echo "Am didn't do anything, use patch"
	patch -p1 --merge < "${PATCH}"
fi
