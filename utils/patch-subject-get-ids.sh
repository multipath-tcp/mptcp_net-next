#!/bin/bash -e

SUBJECT="${*}"

[ -n "${SUBJECT}" ]

# escape special chars for grep
SUBJECT="${SUBJECT//\*/\\\*}"

bash "-${-}" ./.list-pending.sh NO_AUTH | \
	grep " ${SUBJECT}\.*$" | \
	cut -d: -f1 | \
	sort -nr

