#! /bin/bash -e

: "${1?}"

if [ ${#} -gt 1 ]; then
	subject="${1}"
	shift
fi

msgid="${1}"

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

subject="${subject:-$(b4 am --cherry-pick _ --no-add-trailers -o - "${msgid}" |
			grep -A 1 "^Subject: " | grep -e "^Subject: " -e "^ \S")}"
subject="${subject//[$'\n\r'] / }" # on one line
echo "${subject}"

if [ -z "${subject}" ]; then
	printerr "Not able to find the corresponding patch in the subject: pass the commit title as first argument"
	exit 1
fi

# take what is between "" if any
if [ $(echo "${subject}" | grep -o '"' | wc -l) -eq 2 ]; then
	subject="$(echo "${subject}" | cut -d\" -f2)"
elif [ $(echo "${subject}" | grep -o ':' | wc -l) -gt 1 ]; then
	subject="$(echo "${subject}" | cut -d: -f3- | sed 's/"//g;s/^ \+//g')"
fi

git checkout t/upstream
topic="$(./.tg-get-topic.sh "${subject}")"
if [ -z "${topic}" ]; then
	printerr "Topic with subject '${subject}' not found: pass the commit title as first argument"
	exit 1
fi

if ! git checkout "${topic}"; then
	printerr "Unable to checkout to ${topic}"
	exit 1
fi

tg_update

./.am-patch.sh "${msgid}"
