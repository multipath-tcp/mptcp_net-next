#! /bin/bash -x
TG_TOP=$(tg info --series | head -n1 | awk '{ print ( }') ./.add_patch.sh "${@}"
