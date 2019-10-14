DEV="$(git show -s --format="%aN <%aE>" HEAD)"
SIG="Signed-off-by: ${DEV}"
COD="Co-developed-by: ${DEV}"

echo "Adding: ${SIG}"

grep -q "^${SIG}$" .topmsg && echo "Already has: ${SIG}" && exit

LAST_LINE=$(tail -n1 .topmsg)
sed -i '$ d' .topmsg # remove last line
echo "${COD}" >> .topmsg
echo "${SIG}" >> .topmsg
echo "${LAST_LINE}" >> .topmsg
git commit -sm "tg: add $(git show -s --format="%aN" HEAD)' signed-off + codev

After the fix provided in this topic, see:
$(git show -s --format="%h (%s)" HEAD)" .topmsg

printf " - %s: \"Signed-off-by\" + \"Co-developed-by\"\n" \
	"$(git rev-parse --short HEAD)"
