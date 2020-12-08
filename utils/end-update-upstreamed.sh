#!/bin/bash -ex

git checkout --theirs .
git add -u
./.end-conflict.sh
tg patch
