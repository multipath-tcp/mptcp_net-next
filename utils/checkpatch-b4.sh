#! /bin/bash -e

branch=$(git rev-parse --abbrev-ref HEAD)
if [ "${branch:0:3}" != "b4/" ]; then
	echo "Not on a b4 controlled branch? '${branch}'"
	exit 1
fi

./.checkpatch.sh --git "$(b4 prep --show-info | awk '/^start-commit: / { print $2 }').."
