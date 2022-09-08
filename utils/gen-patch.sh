#!/bin/bash -x

TARGET="${TARGET:-mptcp-next}"

# replace -X not accepted by checkpatch with HEAD~X
REF="HEAD~..HEAD"
N=("-1")
for arg in "${@}"; do
	if [[ "${arg}" =~ ^-[0-9]+$ ]]; then
		REF="HEAD~${arg:1}..HEAD"
		N=()
	elif ! [[ "${arg}" =~ ^- ]]; then
		REF="${arg}"
		N=()
	fi
	# continue, just in case we give multiple refs
done

COUNT="$(git rev-list --count "${REF}")"

if [ "${COUNT}" -gt 50 ]; then
	echo "More than 50 commits, something wrong here"
	exit 1
elif [ "${COUNT}" -gt 1 ]; then
	N+=("--cover-letter")
fi

if ! ./.checkpatch.sh --git "${REF}"; then
	echo "There are some errors with CheckPatch. Press Enter to continue."
	read -r
fi

git format-patch \
	--notes \
	--base="${REF%..*}" \
	--subject-prefix="PATCH ${TARGET}" \
	-o "patches/$(git rev-parse --abbrev-ref HEAD)" \
	"${N[@]}" "${@}"
