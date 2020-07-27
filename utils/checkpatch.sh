#!/bin/bash

checkpatch() {
	./scripts/checkpatch.pl --strict --codespell --codespellfile \
		${CP_EXTRA_ARGS} \
		/usr/lib/python3/dist-packages/codespell_lib/data/dictionary.txt \
		"${1}"
}

for patch in "${@}"; do
	checkpatch "${patch}"
done
