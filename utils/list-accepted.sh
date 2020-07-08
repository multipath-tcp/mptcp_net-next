#!/bin/bash

list() {
	echo -n "By: "
	git-pw patch list --state "${1}" -f simple -c Submitter | sed "s/ \(\S\+@\S\+\)//g" | tail -n+3 | sort -u | xargs -n2 -I{} echo -n "{}, " | sed 's/, $//g'
	echo
	PAGER=cat git-pw patch list --state "${1}" -f simple -c ID -c Name
	echo
}

echo "== Accepted in our repo =="
list Accepted
echo "== Deferred =="
list Deferred
