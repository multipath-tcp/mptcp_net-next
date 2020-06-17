#!/bin/bash -x
git format-patch --notes ${1+--cover-letter} --subject-prefix="PATCH mptcp-next" -o patches/$(git rev-parse --abbrev-ref HEAD) ${1:--1}
