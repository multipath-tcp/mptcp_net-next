#!/bin/bash -ex
mkdir -p patches
cp ../scripts/ci/virtme.sh patches/
bash -x ../scripts/ci/Dockerfile.virtme.sh patches/virtme.sh "${@}"
