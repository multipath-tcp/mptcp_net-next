#!/bin/bash

git am --continue
printf " - %s: \"squashed\" (with conflicts) in \"%s\"\n" \
	"$(git rev-parse --short HEAD)" \
	"$(./.title.sh)"
./.signed-off.sh
