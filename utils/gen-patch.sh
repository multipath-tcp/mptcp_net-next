#!/bin/bash -x
git format-patch --notes --subject-prefix="PATCH mptcp-next" -o patches/$(git rev-parse --abbrev-ref HEAD) "${@:--1}"
