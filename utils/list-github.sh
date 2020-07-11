#!/bin/bash -e

# $@: args
my_ghi() {
	ghi list --sort created --no-pulls "${@}" | \
		sed "s/ [0-9]\+$//g;s/ [0-9]\+ @/ @/g;s/ $//g"
}

echo "== Open =="
my_ghi --state open

echo
echo "== Close =="
my_ghi --state closed --since "$(date -dlast-week +%Y-%m-%d)"
