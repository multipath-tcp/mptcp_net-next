#! /bin/bash -ex

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

TARGET="${1}"

sync_upstream() {
	[ "${TARGET}" = "new" ]
}

update_local_tree() {
	TG_TOP="${1}" \
		TG_UPSTREAM_RANGE="${2}" \
		TG_PUSH=0 \
		./.publish.sh
}

update() {
	local base="${1}"
	local top="${2}"
	local before range

	git checkout "${base}"
	before=$(git rev-parse HEAD)

	if sync_upstream; then
		local new_base
		if [ "${base}" = "${TG_BASE_NET_NEXT}" ]; then
			git fetch "git://git.kernel.org/pub/scm/linux/kernel/git/netdev/${base}.git" master
			new_base=FETCH_HEAD
		else
			git fetch "git://git.kernel.org/pub/scm/linux/kernel/git/netdev/${base}.git" master
			new_base=$(git merge-base FETCH_HEAD "${TG_BASE_NET_NEXT}")
		fi
		git merge --no-stat --ff-only "${new_base}"

		git fetch origin
		range="${before}..${base}"
	else
		git pull origin "${base}"
		range=0
	fi

	tg remote origin --populate

	update_local_tree "${top}" "${range}"
	if [ "${top}" = "${TG_BASE_NET}" ]; then
		# we also need to update the net-next part
		update_local_tree "${TG_TOPIC_TOP_NET_NEXT}" "${range}"
	fi

	git --no-pager diff --stat "${before}..${base}"
}

update "${TG_BASE_NET_NEXT}" "${TG_TOPIC_TOP_NET_NEXT}"
update "${TG_BASE_NET}" "${TG_TOPIC_TOP_NET}"

if sync_upstream; then
	echo "remove empty topics & push?"
	read -r
	./.tg-remove-empty.sh
fi
