#!/bin/bash -e

SOB="Signed-off-by"
SENDER="${SOB}: ${1:?"Usage: ${0} 'NAME <EMAIL>'"}"
END="${2:-}"

add_signed_off_if_needed() {
	if grep -q "${SENDER}" .topmsg; then
		echo "${SOB} already there"
	else
		echo "Adding ${SOB}"
		echo "${SENDER}" >> .topmsg
		git add .topmsg
		git commit -sm "tg:msg: add sender' ${SOB}"
	fi
}

next() {
	[ "$(git rev-parse --abbrev-ref HEAD)" = "${END}" ] && return 1
	echo 1 | tg checkout next
}

./.tg-first.sh
add_signed_off_if_needed
while next; do
	tg update
	./.title.sh
	add_signed_off_if_needed
done
tg push
