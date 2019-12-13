#!/bin/bash
git format-patch --notes ${1+--cover-letter} -o patches/$(git rev-parse --abbrev-ref HEAD) ${1:--1}
