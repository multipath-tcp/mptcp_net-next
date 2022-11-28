#! /bin/bash -e
: "${1?}"
tg info --series | grep "\[PATCH\] ${*}$" | sed 's/^. //g' | awk '{ print $1 }'
