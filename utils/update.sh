#! /bin/bash -ex
git checkout net-next
NET_NEXT_BEFORE=$(git rev-parse HEAD)
git fetch origin
if [ "${1}" = "new" ]; then
	git pull --ff-only git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git master
elif [ -n "${1}" ]; then
	git reset --hard "${@}"
else
	git pull origin
fi
tg remote origin --populate

TG_PUSH=0 ./.publish.sh

git --no-pager diff --stat "${NET_NEXT_BEFORE}"..net-next

if [ -n "${1}" ]; then
	echo "push?"
	read
	tg push
fi
