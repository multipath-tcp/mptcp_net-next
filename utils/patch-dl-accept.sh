#!/bin/bash -e
git-pw patch download ${1}
git-pw patch update --state accepted ${1}
