#!/bin/bash

list() {
	echo -n "By: "
	git-pw patch list --limit 250 --state "${1}" -f simple -c Submitter | \
		sed "s/ \(\S\+@\S\+\)//g" | \
		tail -n+3 | \
		sort -u | \
		xargs -I{} echo -n "{}, " | \
		sed 's/, $//g'
	echo
	PAGER=cat git-pw patch list --limit 250 --state "${1}" -f simple -c ID -c Name | \
		sed 's/ $//g'
	echo
}

echo "== Accepted in our repo =="
list Accepted
echo "== Deferred =="
list Deferred
echo "== Handled elsewhere =="
list handled-elsewhere
echo "== Mainlined =="
list Mainlined
echo "== Not Applicable =="
list not-applicable
