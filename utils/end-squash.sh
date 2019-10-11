#!/bin/bash

git am --continue
printf " - %s: \"squashed\" in \"%s\"\n" \
	"$(git rev-parse --short HEAD)" \
	"$(./.title.sh)"
./.signed-off.sh
