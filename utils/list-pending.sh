#!/bin/bash
pwclient list -a no -f "%{id}: %{state}: %{name}" | \
	grep -v -e ": Accepted:" -e ": Superseded:" -e ": Deferred:" -e ": Mainlined:" -e ": Not Applicable:" -e ": Handled Elsewhere:"

echo
echo "Duplicated:"
pwclient list -a no -f "%{state}:%{name}" | \
	grep -v -e "^Superseded:" -e "^Deferred:" -e "^Mainlined:" -e "^Not Applicable:" -e "^Handled Elsewhere:" | \
	cut -d: -f2- | \
	sed 's/\[.\+\]//g;s/^\s\+//g' | \
	sort | \
	uniq -cd

echo
echo -n "By: "
pwclient list -a no -f "%{state}#%{submitter}" | \
	grep -v -e "^Accepted#" -e "^Superseded#" -e "^Deferred#" -e "^Mainlined#" -e "^Not Applicable#" -e "^Handled Elsewhere#" | \
	cut -d\# -f2- | \
	cut -d\< -f1 | \
	sed "s/ $//g" | \
	sort -u | \
	xargs -I{} echo -n "{}, "
echo
