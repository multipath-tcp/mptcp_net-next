#!/bin/bash

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

DEV="$(git show -s --format="%aN <%aE>" HEAD)"
SIG="Signed-off-by: ${DEV}"
COD="Co-developed-by: ${DEV}"

printinfo "Adding: ${SIG}"

if grep -q "^${SIG}$" .topmsg; then
	printinfo "Already has: ${SIG}"
	exit
fi

LAST_LINE=$(tail -n1 .topmsg)
sed -i '$ d' .topmsg # remove last line
echo "${COD}" >> .topmsg
echo "${SIG}" >> .topmsg
echo "${LAST_LINE}" >> .topmsg
git commit -sm "tg: add $(git show -s --format="%aN" HEAD)' signed-off + codev

After the fix provided in this topic, see:
$(git show -s --format="%h (%s)" HEAD)" .topmsg

print " - $(git rev-parse --short HEAD): \"Signed-off-by\" + \"Co-developed-by\""
