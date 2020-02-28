#!/bin/bash

git show --format=email HEAD"${1:+~${1}}" | ./scripts/checkpatch.pl --strict --codespell --codespellfile /usr/lib/python3/dist-packages/codespell_lib/data/dictionary.txt
