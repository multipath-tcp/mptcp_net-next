#! /bin/bash -ex

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

TARGET="${1}"
SYNC_NET="${2:-new}"

sync_net() {
	[ "${TARGET}" = "${SYNC_NET}" ]
}

sync_upstream() {
	[ "${TARGET}" = "new" ] || sync_net
}

update_local_tree() {
	TG_TOP="${1}" TG_UPSTREAM_RANGE="${2}" \
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

		git fetch "git://git.kernel.org/pub/scm/linux/kernel/git/netdev/${base}.git" main

		if [ "${base}" = "${TG_BASE_NET_NEXT}" ] || sync_net; then
			new_base=FETCH_HEAD
		else
			new_base=$(git merge-base FETCH_HEAD "${TG_BASE_NET_NEXT}")

			if git merge-base --is-ancestor "${TG_BASE_NET}" "${new_base}"; then
				echo "Going to update the -net base (if new_base is different)"
			else
				echo "The -net base is newer than the common commit, no modif"
				new_base="${TG_BASE_NET}"
			fi
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
	if [ "${top}" = "${TG_TOPIC_TOP_NET}" ]; then
		# we also need to update the net-next part
		update_local_tree "${TG_TOPIC_TOP_NET_NEXT}" "${range}"
	fi

	git --no-pager diff --stat "${before}..${base}"
}

if [ "$(git status --porcelain --untracked-files=no | wc -l)" != 0 ]; then
	printinfo "There are modified files that might be wiped during the update."
	printinfo "Press Enter to continue."
	read -r
fi

update "${TG_BASE_NET_NEXT}" "${TG_TOPIC_TOP_NET_NEXT}"
update "${TG_BASE_NET}" "${TG_TOPIC_TOP_NET}"

if sync_upstream; then
	echo "remove empty topics & push?"
	read -r
	./.tg-remove-empty.sh
fi

# Switch to upstream top, not -net
git checkout "${TG_TOPIC_TOP_NET_NEXT}"
