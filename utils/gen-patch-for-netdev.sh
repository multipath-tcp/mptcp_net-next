#!/bin/bash -ex

[ "${1}" = "net" ] || [ "${1}" = "net-next" ]

TARGET="${1}"
shift

git format-patch --subject-prefix="PATCH ${TARGET}" -o "patches/$(git rev-parse --abbrev-ref HEAD)" --notes "${@}"
