#!/bin/bash -ex

: "${1:?}"

git fetch netdev-net
git fetch netdev-next
git fetch origin

git branch --remote --contains "${1}" netdev-net/master netdev-next/master origin/export
