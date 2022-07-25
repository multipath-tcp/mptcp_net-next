#!/bin/bash -ex

: "${1:?}"

git fetch --tags netdev-net
git fetch --tags netdev-next
git fetch origin

git branch --remote --contains "${1}" netdev-net/main netdev-next/main origin/export
git tag --list v"[5-9]*" --contains="${1}" | sort -V | head -n1
