#! /bin/bash -e

MAX_PERIOD=$((60*60*24*30)) # 1 month
NOW=$(date +%s)
ORIGIN="origin"
REFS="refs/remotes/${ORIGIN}"

echo "Get branches"
mapfile -t NEXT <<< "$(tg info --series t/upstream | awk '{print $1}')"
mapfile -t NET <<< "$(tg info --series t/upstream-net | awk '{print $1}')"

unset ALL
declare -A ALL

for i in "${NEXT[@]}" "${NET[@]}"; do
	ALL["${i}"]=1
done

mapfile -t REMOTE <<< "$(git for-each-ref --format='%(refname:lstrip=3)' "${REFS}/t/")"
ORPHAN=()
for i in "${REMOTE[@]}"; do
	if [[ -z "${ALL[${i}]}" ]]; then
		ORPHAN+=("${i}")
	fi
done

echo "Check date"
echo "=== $(date -R) ===" >> .tg-delete-old-branches.log
DELETE=()
TB=()
for i in "${ORPHAN[@]}"; do
	SHA=$(git rev-parse "${REFS}/${i}")
	CDATE=$(git log -1 --format="format:%ct" "${SHA}")
	if [[ $((NOW - CDATE)) -ge ${MAX_PERIOD} ]]; then
		DELETE+=("${i}")
		BASE="refs/top-bases/${i}"
		echo "${i} ${SHA}" >> .tg-delete-old-branches.log
		TG+=("${BASE}")
		echo "${BASE} $(git rev-parse "${REFS}/${BASE}")" >> .tg-delete-old-branches.log
	fi
done

if [[ ${#DELETE[@]} -eq 0 ]]; then
	echo "Nothing to delete"
	exit 0
fi

echo "Delete: ${#DELETE[@]}"
git push --delete "${ORIGIN}" "${DELETE[@]}" "${TB[@]}"
git branch -D "${DELETE[@]}" "${TB[@]}"
