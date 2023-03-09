#! /bin/bash -e
: "${1?}"
git switch "$(./.tg-get-topic.sh "${@}")"
