#!/bin/bash

git commit -sm "Squash to \"$(./.title.sh "${1:-HEAD}")\"" -e
./.notes-squash.sh HEAD "${1:-HEAD}"
