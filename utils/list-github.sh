#!/bin/bash -e

# $@: args
my_ghi() {
	ghi list --sort created --no-pulls "${@}" | \
		sed "s/ [0-9]\+$//g;s/ [0-9]\+ @/ @/g;s/ $//g"
}

LAST_WEEK="$(date -dlast-week +%Y-%m-%d)"

echo "    Recently opened (latest from last week: *TODO*)"
echo
my_ghi --state open --since "${LAST_WEEK}"

echo
echo "    Bugs (open and flagged as \"bug\")"
echo
my_ghi --state open -L bug

echo
echo "    In Progress (open and assigned to someone)"
echo
my_ghi --state open -N bug | grep " @"

echo
echo "    Recently closed (since last week)"
echo
my_ghi --state closed --since "${LAST_WEEK}"
