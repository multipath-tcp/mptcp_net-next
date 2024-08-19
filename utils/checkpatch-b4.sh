#! /bin/bash -e

branch=$(git rev-parse --abbrev-ref HEAD)
if [ "${branch:0:3}" != "b4/" ]; then
	echo "Not on a b4 controlled branch? '${branch}'"
	exit 1
fi

rc=0
./.checkpatch.sh --git "$(b4 prep --show-info start-commit).." || rc=$?

echo
b4 prep --check

prefixes="$(b4 prep --show-info prefixes)"
echo
echo "Prefixes: ${prefixes}"
if [[ "${prefixes}" == *"-next"* ]] &&
   git log --format="%b" "$(b4 prep --show-info series-range)" | grep -q "^Fixes: "; then
	echo -e "\n\tWARNING: Series is for ${prefixes}, but there are patches with 'Fixes' tags\n"
	exit 1
fi
exit ${rc}
