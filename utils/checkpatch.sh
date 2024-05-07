#!/bin/bash

checkpatch() {
	./scripts/checkpatch.pl --strict --codespell --codespellfile \
		/usr/lib/python3/dist-packages/codespell_lib/data/dictionary.txt \
		"${@}"
}

if [ "${1}" = "--git" ]; then
	checkpatch "${@}"
else
	for patch in "${@}"; do
		checkpatch "${patch}"
	done
fi
