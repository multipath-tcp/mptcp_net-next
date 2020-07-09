#!/bin/bash -e

git am --continue
SHA="$(git rev-parse --short HEAD)"
COMMIT="$(git rev-parse HEAD)"
TITLE="$(git show --pretty="format:%s")"
printf " - %s: \"squashed\" (with conflicts) in \"%s\"\n" \
	"${SHA}" \
	"$(./.title.sh)"
./.signed-off.sh
./.patch-subject-accept.sh "${TITLE}" "${COMMIT}"
