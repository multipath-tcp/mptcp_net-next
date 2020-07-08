#!/bin/bash -ex

git checkout --theirs .
git add -u
./.end-conflict.sh
tg patch
echo "Press OK to continue"
read
tg update --continue
tg push
