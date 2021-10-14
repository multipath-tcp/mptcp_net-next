#!/bin/bash

_dup() {
	# shellcheck disable=SC2086
	pwclient list -a no -f "%{state}:%{name}" | \
		grep ${1} -e "^Superseded:" -e "^Deferred:" -e "^Mainlined:" -e "^Not Applicable:" | \
		cut -d: -f2- | \
		sed 's/\[.\+\]//g;s/^\s\+//g' | \
		sort | \
		uniq -cd
}

dup() { local d
	d="$(_dup "${2}")"
	if [ -n "${d}" ]; then
		echo "There are duplicated entries for ${1}:"
		echo "${d}"
		exit 1
	fi
	echo "No duplicated entries for ${1}"
	echo
}

list() { local s
	if [ -z "${2}" ] && [ "$(git-pw patch list --state "${1}" -f csv -c ID | wc -l)" -le 1 ]; then
		return 0
	fi

	echo -n "    ${2:-${1}} (by: "
	s=$(git-pw patch list --limit 250 --state "${1}" -f simple -c Submitter | \
		sed "s/ \(\S\+@\S\+\)//g" | \
		tail -n+3 | \
		sort -u | \
		xargs -r -I{} echo -n "{}, ")
	echo "${s}" | sed 's/, $//g;s/^$/\//g;s/$/):/g'
	echo
	s="$(PAGER="cat" git-pw patch list --limit 250 --state "${1}" -f simple -c ID -c Name | \
		tail -n+3)"
	echo "${s}" | sed 's/^$/\//g'
	echo
	echo
}

# pwclient to list more than one state
list_repo() { local w
	w="$(pwclient list -a no -f "%{state}#%{submitter}" | \
		grep -v -e "^Accepted#" -e "^Superseded#" -e "^Deferred#" -e "^Mainlined#" -e "^Not Applicable#" | \
		cut -d\# -f2- | \
		cut -d\< -f1 | \
		sed "s/ $//g" | \
		sort -u | \
		xargs -I{} echo -n "{}, " | \
		sed 's/, $//g')"

	echo "    our repo (by: ${w:-/}):"
	echo
	pwclient list -a no -f "%{id}: %{state}: %{name}" | \
		grep -v -e ": Accepted:" -e ": Superseded:" -e ": Deferred:" -e ": Mainlined:" -e ": Not Applicable:"
}

dup "Repo" "-v"
dup "Upstream"


cat <<'EOF'
Accepted patches:
    - The list of accepted patches can be seen on PatchWork:
      https://patchwork.kernel.org/project/mptcp/list/?state=3


EOF

list Mainlined "netdev (if mptcp ML is in cc)"
list Accepted "our repo"

cat <<'EOF'

Pending patches:
    - The list of pending patches can be seen on PatchWork:
      https://patchwork.kernel.org/project/mptcp/list/?state=*


EOF

list handle-elsewhere "netdev (if mptcp ML is in cc)"
list_repo

cat <<'EOF'


Extra, just in case

EOF
list Deferred
list not-applicable
