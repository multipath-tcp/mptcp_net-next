#!/bin/bash
tg patch ${1:+"${1}"} | \
	./scripts/checkpatch.pl --strict --codespell \
	--codespellfile /usr/lib/python3/dist-packages/codespell_lib/data/dictionary.txt \
	--max-line-length=80
