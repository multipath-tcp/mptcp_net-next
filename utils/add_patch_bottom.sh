#! /bin/bash -e
if [ -n "${TG_TOP}" ]; then
	echo "TG_TOP is already defined: ${TG_TOP}"
	exit 1
fi

git checkout t/upstream

TG_TOP=$(tg info --series | head -n1 | awk '{ print $1 }') ./.add_patch.sh "${@}"
