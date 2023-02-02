#!/bin/bash -e

: "${1:?}"

git fetch -f --multiple --tags netdev-net netdev-next
git fetch origin

git branch --remote --contains "${1}" netdev-net/main netdev-next/main origin/export
git tag --list v"[5-9]*" --contains="${1}" | sort -V | head -n1
