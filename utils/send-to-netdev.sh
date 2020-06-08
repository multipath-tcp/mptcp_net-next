#!/bin/bash -ex

[ -f "${1}" ]

DRY_RUN=""
[ "${GO}" != 1 ] && DRY_RUN="--dry-run"

git send-email ${DRY_RUN} --to="netdev@vger.kernel.org" --cc-cmd="./scripts/get_maintainer.pl --norolestats '${1}'" --annotate "${1}"

if [ "${GO}" != 1 ]; then echo "Use GO=1 to actually send it"; fi
