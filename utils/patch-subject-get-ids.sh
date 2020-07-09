#!/bin/bash -e

SUBJECT="${*}"

[ -n "${SUBJECT}" ]

bash "-${-}" ./.list-pending.sh NO_AUTH | \
	grep -E "(:|: \[.+\]) ${SUBJECT}$" | \
	cut -d: -f1 | \
	sort -nr

