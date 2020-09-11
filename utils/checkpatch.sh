#!/bin/bash

checkpatch() {
	./scripts/checkpatch.pl --strict --codespell --codespellfile \
		/usr/lib/python3/dist-packages/codespell_lib/data/dictionary.txt \
		${CP_EXTRA_ARGS} \
		"${1}"
}

for patch in "${@}"; do
	checkpatch "${patch}"
done
