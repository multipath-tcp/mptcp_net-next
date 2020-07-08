#!/bin/bash
pwclient list -a no -f "%{id}: %{state}: %{name}" | grep -v ": Accepted:" | grep -v ": Superseded:" | grep -v ": Deferred:"
echo -n "By: "
pwclient list -a no -f "%{state}#%{submitter}" | grep -v "^Accepted#" | grep -v "^Superseded#" | grep -v "^Deferred#" | cut -d\# -f2- | cut -d\< -f1 | sed "s/ $//g" | sort -u | xargs -n2 -I{} echo -n "{}, "
echo
