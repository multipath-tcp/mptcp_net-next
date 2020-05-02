#! /bin/bash -x
TG_TOP=$(tg info --series | head -n1 | awk '{ print $1 }') ./.add_patch.sh "${@}"
