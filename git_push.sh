#! /bin/bash -e

git push "${@}" origin HEAD:scripts

trap 'git config --local push.gpgsign true' EXIT

git config --local push.gpgsign false
git push "${@}" github HEAD:scripts
