#!/bin/bash -e

# $@: args
my_ghi() {
	ghi list --sort created --no-pulls "${@}" | \
		sed "s/ [0-9]\+$//g;s/ [0-9]\+ @/ @/g;s/ $//g"
}

LAST_WEEK="$(date -dlast-week +%Y-%m-%d)"

echo "== Recently Open =="
my_ghi --state open --since "${LAST_WEEK}"

echo
echo "== Bugs =="
my_ghi --state open -L bug

echo
echo "== In progress =="
my_ghi --state open -N bug | grep " @"

echo
echo "== Recently Close =="
my_ghi --state closed --since "${LAST_WEEK}"
