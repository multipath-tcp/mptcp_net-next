#! /bin/bash -e
: "${1?}"
tg info --series=t/upstream | grep "\[PATCH\] ${*}$" | sed 's/^. //g' | awk '{ print $1 }'
