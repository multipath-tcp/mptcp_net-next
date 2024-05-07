#!/bin/bash -e

git am --continue
SHA="$(git rev-parse --short HEAD)"
COMMIT="$(git rev-parse HEAD)"
TITLE="$(git log -1 --pretty="format:%s")"
printf "%s%s: \"squashed\" (with conflicts) in \"%s\"\n" "- " \
	"${SHA}" \
	"$(./.title.sh)"
./.signed-off.sh
./.patch-subject-accept.sh "${TITLE}" "${COMMIT}"
