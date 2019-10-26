#!/bin/bash
git notes add -fm "to be squashed in \"$(./.title.sh)\"" "${1:-HEAD}"
