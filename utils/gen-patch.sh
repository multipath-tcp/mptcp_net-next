#!/bin/bash
git format-patch --notes -o patches/$(git rev-parse --abbrev-ref HEAD) "${1:--1}"
