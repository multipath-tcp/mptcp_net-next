#!/bin/bash
./.tg-first.sh
./.tg-checkpatch.sh
while echo 1 | tg checkout next; do
	./.title.sh
	./.tg-checkpatch.sh
done
