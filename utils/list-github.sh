#!/bin/bash

# $@: args
my_ghi() {
	ghi list --sort created --no-pulls "${@}" |
		sed "s/ [0-9]\+$//g;s/ [0-9]\+ @/ @/g;s/ $//g" |
		grep -v "^# multipath-tcp/mptcp_net-next"
}

LAST_MEETING="${1:-$(date -dlast-week +%Y-%m-%d)}"

echo "    Recently opened (latest from the last meeting: *TODO*)"
echo
my_ghi --state open --since "${LAST_MEETING}"

echo
echo
echo "    Bugs (opened, flagged as \"bug\" and assigned)"
echo
my_ghi --state open -L bug | grep -e "^None.$" -e " @" | awk '{ print } END { if (NR == 0) { print "None." }  }'

echo
echo
echo "    Bugs (opened and flagged as \"bug\" and not assigned)"
echo
my_ghi --state open -L bug | grep -v " @"

echo
echo
echo "    In Progress (opened, new feature and assigned)"
echo
my_ghi --state open -L enhancement | grep -e "^None.$" -e " @" | awk '{ print } END { if (NR == 0) { print "None." }  }'

echo
echo
echo "    Assigned Questions (opened, questions and assigned)"
echo
my_ghi --state open -L question | grep -e "^None.$" -e " @" | awk '{ print } END { if (NR == 0) { print "None." }  }'

echo
echo
echo "    Open questions (opened, questions and not assigned)"
echo
my_ghi --state open -L question | grep -v " @"

echo
echo
echo "    For later (opened and not assigned assigned)"
echo
my_ghi --state open -N bug -N question | grep -v " @"

echo
echo
echo "    Recently closed (since ${LAST_MEETING})"
echo
my_ghi --state closed --since "${LAST_MEETING}"
