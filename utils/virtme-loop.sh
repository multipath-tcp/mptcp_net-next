#!/bin/bash

MODE=("${@:-expect-normal}")

echo "Starting mode ${MODE[*]}: $(date -R)"

i=1
while INPUT_NO_BLOCK=1 ./.virtme.sh "${MODE[@]}"; do
	i=$((i+1))
	echo -e "\n\n\n=== Starting attempt $i: $(date -R) ===\n\n\n"
done

echo "Stopped after $i attempts"
date -R
