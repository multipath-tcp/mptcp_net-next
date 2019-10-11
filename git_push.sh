#! /bin/bash

trap 'git config --local push.gpgsign true' EXIT

git config --local push.gpgsign false
git push "${@}" github HEAD:scripts
