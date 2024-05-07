#!/bin/bash -e

FILE="${1}"
[ -s "${FILE}" ]

COMMIT="${2}"

SUBJECT_2L="$(grep -A1 "^Subject: " "${FILE}" | head -n2)"
[ -n "${SUBJECT_2L}" ]

# remove 'Subject: '
SUBJECT_2L="${SUBJECT_2L:9}"

# we can have the subject on 2 lines (or more)
if echo "${SUBJECT_2L}" | tail -n1 | grep -q "^\S"; then
	SUBJECT="$(echo "${SUBJECT_2L}" | head -n1)"
else
	SUBJECT="$(echo "${SUBJECT_2L}" | tr -d '\n')"
fi

# remove '[xxx]' and \r
SUBJECT="$(echo "${SUBJECT}" | sed -e "s/\[.\+\] //g;s/\\r$//g")"

[ -n "${SUBJECT}" ]

bash "-${-}" ./.patch-subject-accept.sh "${SUBJECT}" "${COMMIT}"
