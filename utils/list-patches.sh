#!/bin/bash

# $@: list of --state X
_dup() {
	git-pw patch list --limit 250 -c Name -f simple "${@}" |
		sed 's/\[.\+\]//g;s/^\s\+//g' |
		tail -n+3 |
		sort | uniq -cd
}

dup_Upstream() {
	_dup --state deferred \
	     --state mainlined \
	     --state not-applicable \
	     --state handled-elsewhere
}

dup_Repo() {
	_dup --state new \
	     --state under-review \
	     --state accepted \
	     --state rejected \
	     --state rfc \
	     --state not-applicable \
	     --state changes-requested \
	     --state queued \
	     --state awaiting-upstream \
	     --state needs-ack
}

dup() { local d
	d="$(dup_"${1}")"
	if [ -n "${d}" ]; then
		echo "There are duplicated entries for ${1}:"
		echo "${d}"
		echo
		echo "Press Enter to continue"
		read
	fi
	echo "No duplicated entries for ${1}"
	echo
}

list() { local list desc id name state tag n patch submitter series sid url
	desc="${1}"
	shift

	if [ -z "${desc}" ] && [ "$(git-pw patch list --limit 250 --state "${@}" -f csv -c ID | wc -l)" -le 1 ]; then
		return 0
	fi

	echo -n "    ${desc:-${1}} (by: "

	list=$(git-pw patch list --sort date --limit 250 --state "${@}" -f simple -c ID -c Submitter |
		sed "s/ \(\S\+@\S\+\)//g" |
		tail -n+3)
	if [ -z "${list}" ]; then
		echo "/):"
		echo
		echo "/"
		echo
		echo
		return
	fi

	echo "${list}" | cut -d\  -f2- |
		sort -u |
		xargs -r -I{} echo -n "{}, " |
		sed 's/, $//g;s/^$/\//g;s/$/):/g'
	echo
	echo

	for id in $(echo "${list}" | cut -d\  -f1); do
		patch="$(git-pw patch show --format csv "${id}" | sed 's/""/#/g')"
		name=$(echo "${patch}" | grep '^"Name",' | cut -d\" -f4)

		echo -n "${id}: ${name//#/\"}"

		tag=$(echo "${name}" | sed 's/.*\(\[.\+\]\).*/\1/')
		if [ "${tag:0:1}" = '[' ]; then
			n=$(echo "${tag}" | sed 's#.*\b\([0-9]\+/[0-9]\+\)\b.*#\1#')
			if [[ "${n:0:1}" == [0-9] ]]; then
				# if we have multiple patches, we only display info
				# for the last one
				if [ "${n%/*}" != "${n#*/}" ]; then
					echo
					continue
				else
					n="series"
				fi
			fi
		fi

		echo ":"

		state=$(echo "${patch}" | grep '^"State",' | cut -d\" -f4)
		series=$(echo "${patch}" | grep '^"Series",' | cut -d\" -f4)
		sid=${series%% *}
		series=${series#* }
		submitter=$(echo "${patch}" | grep '^"Submitter",' | cut -d\" -f4 | sed 's/ \(\S\+@\S\+\)//')
		url=$(echo "${patch}" | grep '^"URL",' | cut -d\" -f4)

		# No need to display more info for this "RESEND" series
		if [ "${sid}" = 489001 ] || [ "${sid}" = 489003 ]; then
			continue
		fi

		# more than one state
		if [ "${#}" -gt 1 ]; then
			[ "${state}" = "rfc" ] && state=RFC || state=${state//-/ }
			echo "      - State: ${state^}"
		fi

		if [ "${n}" = "series" ]; then
			url="https://patchwork.kernel.org/project/mptcp/list/?series=${sid}&state=*&archive=both"

			echo "      - Series: ${series//#/\"}"
		fi

		echo "      - Submitter: ${submitter//#/\"}"
		echo "      - URL: ${url//#/\"}"
		echo
	done

	echo
}

dup "Repo"
dup "Upstream"


cat <<'EOF'
Accepted patches:
    - The list of accepted patches can be seen on PatchWork:
      https://patchwork.kernel.org/project/mptcp/list/?state=3


EOF

list "netdev (if mptcp ML is in cc)" mainlined
list "our repo" accepted

cat <<'EOF'

Pending patches:
    - The list of pending patches can be seen on PatchWork:
      https://patchwork.kernel.org/project/mptcp/list/?state=*


EOF

list "netdev (if mptcp ML is in cc)" handled-elsewhere
list "our repo" new \
	--state under-review \
	--state rejected \
	--state rfc \
	--state changes-requested \
	--state awaiting-upstream \
	--state queued \
	--state needs-ack

cat <<'EOF'


Extra, just in case

EOF
list "" deferred
list "" not-applicable
