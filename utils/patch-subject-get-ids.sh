#!/bin/bash -e

SUBJECT="${*}"

[ -n "${SUBJECT}" ]

bash "-${-}" ./.list-pending.sh NO_AUTH | \
	grep " ${SUBJECT}$" | \
	cut -d: -f1 | \
	sort -nr

