#! /bin/bash -e

commit="${1?}"
shift

topic=$(./.tg-get-topic.sh "${commit}")
TG_TOP="${topic}" ./.add_patch.sh "${@}"
