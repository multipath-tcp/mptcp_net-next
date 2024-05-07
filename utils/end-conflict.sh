#!/bin/bash -e

git commit -s --no-edit
printf "%s%s: conflict in %s\n" "- " \
	"$(git rev-parse --short HEAD)" \
	"$(git rev-parse --abbrev-ref HEAD)"
