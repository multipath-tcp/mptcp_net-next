#! /bin/bash -e
git checkout t/upstream
TG_TOP=$(tg info --series | head -n1 | awk '{ print $1 }') ./.add_patch.sh "${@}"
