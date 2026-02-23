#! /bin/bash -e

branch=$(git rev-parse --abbrev-ref HEAD)
if [ "${branch:0:3}" != "b4/" ]; then
	echo "Not on a b4 controlled branch? '${branch}'"
	exit 1
fi

rc=0
#b4 -c "b4.prep-perpatch-check-cmd=./scripts/checkpatch.pl -q --terse --no-summary --mailback --showfile --strict --codespell --codespellfile /usr/lib/python3/dist-packages/codespell_lib/data/dictionary.txt --max-line-length=80" prep --check || rc=$?
./.checkpatch.sh --git "$(b4 prep --show-info start-commit).." || rc=$?
b4 prep --check

prefixes="$(b4 prep --show-info prefixes)"
echo
echo "Prefixes: ${prefixes}"

has_fixes() {
	git log --format="%b" "$(b4 prep --show-info series-range)" | grep -q "^Fixes: "
}

has_stable() {
	git log --format="%b" "$(b4 prep --show-info series-range)" | grep -q "stable@vger.kernel.org"
}

if [[ "${prefixes}" == *"-next"* ]]; then
	if has_fixes; then
		echo -e "\n\tWARNING: Series is for ${prefixes}, but there are patches with 'Fixes' tags"
		echo -e "\t\t$ b4 prep --set-prefixes 'mptcp-net'\n"
		exit 1
	fi
elif [[ "${prefixes}" != "mptcp"* ]] && has_fixes && ! has_stable; then
	echo -e "\n\tWARNING: Series is for ${prefixes}, there are patches with 'Fixes' tags but no patches Ccing Stable"
	exit 1
fi
exit ${rc}
