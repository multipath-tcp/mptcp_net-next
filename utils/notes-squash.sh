#!/bin/bash
git notes add -fm "to be squashed in \"$(./.title.sh ${2:-HEAD})\"" "${1:-HEAD}"
