#!/bin/bash
pwclient list -a no -f "%{id}: %{state}: %{name}" | \
	grep -v ": Accepted:" | \
	grep -v ": Superseded:" | \
	grep -v ": Deferred:"

[ "${1}" = "NO_AUTH" ] && exit 0

echo
echo "Duplicated:"
pwclient list -a no -f "%{state}:%{name}" | \
	grep -v -e "^Superseded:" -e "^Deferred:" | \
	cut -d: -f2- | \
	sed 's/\[.\+\]//g;s/^\s\+//g' | \
	sort | \
	uniq -cd

echo
echo -n "By: "
pwclient list -a no -f "%{state}#%{submitter}" | \
	grep -v "^Accepted#" | \
	grep -v "^Superseded#" | \
	grep -v "^Deferred#" | \
	cut -d\# -f2- | \
	cut -d\< -f1 | \
	sed "s/ $//g" | \
	sort -u | \
	xargs -I{} echo -n "{}, "
echo
