#! /bin/bash -e

: "${1?}"

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

subject="$(b4 am --no-parent -T -o - "${1}" | grep "^Subject: " | head -n 1 | cut -d\" -f2)"
if [ -z "${subject}" ]; then
	printerr "Not double quote in the subject: not a squash-to patch?"
	exit 1
fi

git checkout t/upstream
topic="$(./.tg-get-topic.sh "${subject}")"
if [ -z "${topic}" ]; then
	printerr "Topic with subject '${subject}' not found: on a TopGit branch?"
	exit 1
fi

if ! git checkout "${topic}"; then
	printerr "Unable to checkout to ${topic}"
	exit 1
fi

tg_update

./.am-patch.sh "${1}"
