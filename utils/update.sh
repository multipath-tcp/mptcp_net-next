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
git checkout t/upstream
tg remote origin --populate
tg update
git --no-pager diff --stat "${NET_NEXT_BEFORE}"..net-next
