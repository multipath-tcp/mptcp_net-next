#! /bin/bash -ex

# revert current patch
tg patch | patch -p1 -R
tg files | xargs git add
git commit -sm "tg: revert $(./.title.sh)

A new version is applied in the next commit."

# apply new one
NO_SOB=1 ./.am-patch.sh "${@}"

git --no-pager log -1 --pretty=format:"From: %an <%ae>$headers%nSubject: [PATCH] %s%n%n%b" > .topmsg
${EDITOR:-vim} .topmsg

if git status --porcelain | awk '{ print $2 }' | grep -q "^\.topmsg$"; then
	git add .topmsg
	git commit -sm "tg:msg: sync with parent commit"
fi
