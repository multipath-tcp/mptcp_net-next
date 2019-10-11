#!/bin/bash

[ ! -f "MAINTAINERS" ] && echo "To be launched from your kernel dir" && exit 1

SETUP_DIR="$(dirname "${0}")"

for script in "${SETUP_DIR}"/*; do
	filename="$(basename "${script}")"
	ln -sfv "${script}" ".${filename}"
done
