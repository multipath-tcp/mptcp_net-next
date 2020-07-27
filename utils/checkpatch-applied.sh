#!/bin/bash

checkpatch() {
	./.checkpatch.sh "${1}"
}

for patch in "${@}"; do
	checkpatch "${patch}" | \
		grep -e "^CHECK: " -e "^WARNING: " -e "^ERROR: " | \
		cut -d: -f2- | \
		sort | uniq -c
	checkpatch "${patch}"

	title=$(grep "^Subject: " "${patch}" | cut -d] -f2)
	sha=$(./.find_patch.sh "${title:1}" | awk '{ print $1 }')
	git show -s --format="Fixes: %h (%s)" "${sha}"
done
