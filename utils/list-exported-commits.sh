#!/bin/bash

git fetch origin

git log --reverse --format="        - [%h] %s (%an)" ${1:-"origin/net-next..origin/export"} | \
	sed -e "s/.*git markup: net-next (.*/\n    - Fixes for other trees:\n/;
	        s/.*git markup: fixes other trees (.*/\n    - Fixes for -net:\n/;
	        s/.*git markup: fixes net (.*/\n    - Fixes for net-next:\n/;
	        s/.*git markup: fixes net-next (.*/\n    - Features for net-next:\n/;
	        /DO-NOT-MERGE/,\$d"
