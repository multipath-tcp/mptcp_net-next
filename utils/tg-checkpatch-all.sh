#!/bin/bash
./.tg-first.sh
./.tg-checkpatch.sh
while tg checkout next; do
	./.title.sh
	./.tg-checkpatch.sh
done
