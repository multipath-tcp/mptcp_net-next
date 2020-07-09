#!/bin/bash -ex

FILE="${1}"
[ -s "${FILE}" ]

COMMIT="${2}"

SUBJECT="$(grep "^Subject: " "${FILE}" | head -n1 | sed -e "s/\[.\+\] //g;s/^Subject: //;s/\\r$//g")"
[ -n "${SUBJECT}" ]

bash "-${-}" ./.patch-subject-accept.sh "${SUBJECT}" "${COMMIT}"
