#!/bin/bash -ex

[ -f "${1}" ]

git send-email --to="netdev@vger.kernel.org" --cc-cmd="./scripts/get_maintainer.pl --norolestats '${1}'" --annotate "${1}"
