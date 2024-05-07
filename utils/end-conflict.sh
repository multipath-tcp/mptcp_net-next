#!/bin/bash -e

git commit -s --no-edit
msg="- $(git rev-parse --short HEAD): conflict in $(git rev-parse --abbrev-ref HEAD)"
printf "%s\n" "${msg}"
wl-copy <<< "${msg}" 2>/dev/null || true
