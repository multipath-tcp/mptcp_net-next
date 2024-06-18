#!/bin/bash

title() {
	echo -e "\n\n    ${*}\n"
}

# $@: args
my_ghi() {
	ghi list --sort created --no-pulls "${@}" |
		sed "s/ [0-9]\+$//g;s/ [0-9]\+ @/ @/g;s/ $//g" |
		grep -v "^# multipath-tcp/mptcp_net-next"
}

gh_pr() {
	gh pr list --json number,author,title,updatedAt \
		--search "draft:false" \
		--template '# {{range .}}{{tablerow .number (timeago .updatedAt) .author.login .title}}{{end}}' \
		-R "${@}" | sed 's/^/  /g'
}

LAST_MEETING="${1:-$(date -dlast-week +%Y-%m-%d)}"

title "Recently opened (latest from the last meeting: *TODO*)"
my_ghi --state open --since "${LAST_MEETING}"

title "Bugs (opened, flagged as \"bug\" and assigned)"
my_ghi --state open -L bug | grep -e "^None.$" -e " @" | awk '{ print } END { if (NR == 0) { print "None." }  }'

title "Bugs (opened and flagged as \"bug\" and not assigned)"
my_ghi --state open -L bug | grep -v " @"

title "In Progress (opened, new feature and assigned)"
my_ghi --state open -L enhancement | grep -e "^None.$" -e " @" | awk '{ print } END { if (NR == 0) { print "None." }  }'

title "Assigned Questions (opened, questions and assigned)"
my_ghi --state open -L question | grep -e "^None.$" -e " @" | awk '{ print } END { if (NR == 0) { print "None." }  }'

title "Open questions (opened, questions and not assigned)"
my_ghi --state open -L question | grep -v " @"

title "For later (opened and not assigned)"
my_ghi --state open -N bug -N question | grep -v " @"

title "Recently closed (since ${LAST_MEETING})"
my_ghi --state closed --since "${LAST_MEETING}"

title "Packetdrill PRs"
gh_pr "multipath-tcp/packetdrill"

title "mptcp.dev PRs"
gh_pr "multipath-tcp/mptcp.dev"
