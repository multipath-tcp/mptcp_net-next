#!/bin/bash -e

git am --continue
SHA="$(git rev-parse --short HEAD)"
COMMIT="$(git rev-parse HEAD)"
TITLE="$(git log -1 --pretty="format:%s")"
MSG="- ${SHA}: \"squashed\" (with conflicts) in \"$(./.title.sh)\""

if ./.signed-off.sh; then
	MSG+=$'\n'
	MSG+="- $(git rev-parse --short HEAD): \"Signed-off-by\" + \"Co-developed-by\""
fi
printf "%s\n" "${MSG}"
wl-copy <<< "${MSG}" 2>/dev/null || true

./.patch-subject-accept.sh "${TITLE}" "${COMMIT}"
