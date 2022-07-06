#! /bin/bash -e

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

TG_TOP="${TG_TOP:-}"
TG_UPSTREAM_RANGE="${TG_UPSTREAM_RANGE:-0}"

tg_up_err() {
	printerr "Please fix the conflicts in another terminal." \
	         "End with ./.end-conflict.sh, then press Enter to continue."
	read -r
}

topic_has_been_upstreamed() { local subject="${1}"
	git log \
		--fixed-strings \
		-i --grep "${subject}" \
		--format="format:==%s==" \
		"${TG_UPSTREAM_RANGE}" | \
			grep -q --fixed-strings -i "==${subject}=="
}

tg_up_upstream() { local subject
	if [ "${TG_UPSTREAM_RANGE}" = "0" ]; then
		return 1
	fi

	subject=$(grep "^Subject: " .topmsg | cut -d\] -f2- | sed "s/^ //")

	if ! topic_has_been_upstreamed "${subject}"; then
		return 1
	fi

	printinfo "The commit '${subject}' has been upstreamed, trying auto-fix:"

	git checkout --theirs .
	git add -u
	git commit -s --no-edit

	if [ -z "$(tg files)" ]; then
		return 0
	fi

	printerr "This topic was supposed to be empty because the commit seems" \
	         "to have been sent upstream. Please fix this by amending the" \
	         "commit in another terminal, then press Enter. Or Ctrl+C then:" \
	         "'tg update --abort'"
	read -r
}

tg_up_conflicts() {
	if ! tg_up_upstream; then
		tg_up_err
	fi
}

tg_update() {
	if ! tg update; then
		tg_up_conflicts

		while ! tg update --continue; do
			tg_up_conflicts
		done
	fi
}

tg_for_review() { local branch_top branch_review tg_conflict_files
	branch_top="${1}"
	branch_review="${2}"

	git branch -f "${branch_review}" origin/"${branch_review}"
	git checkout -f "${branch_review}"
	if ! git merge --no-edit --signoff "${branch_top}"; then
		# the only possible conflict would be with the topgit files, manage this
		tg_conflict_files=$(git status --porcelain | grep -E "^DU\\s.top(deps|msg)$")
		if [ -n "${tg_conflict_files}" ]; then
			echo "${tg_conflict_files}" | awk '{ print $2 }' | xargs git rm
			if ! git commit -s --no-edit; then
				err "Unexpected other conflicts: ${tg_conflict_files}"
				return 1
			fi
		else
			err "Unexpected conflicts when updating ${branch_review}"
			return 1
		fi
	fi

	git push origin "${branch_review}"
}

tg_export() { local branch_top branch_export tag
	branch_top="${1}"
	branch_export="${2}"

	git checkout -f "${branch_top}"

	tg export --force --notes "${branch_export}"
	git push --force origin "${branch_export}"

	if [ "${TG_NO_TAG}" = "1" ]; then
		return
	fi

	tag="${branch_export}/${DATE}"

	# send a tag to Github to keep previous commits: we might have refs to them
	git tag "${tag}" "${branch_export}"
	git push origin "${tag}"

	printinfo "Tests are now in progress:\\n"
	printinfo "https://cirrus-ci.com/github/multipath-tcp/mptcp_net-next/${tag}"
	# printinfo "https://github.com/multipath-tcp/mptcp_net-next/actions/workflows/build-validation.yml?query=branch:${branch_export}"
}

publish() { local top review old_rev new_rev
	top="${1}"
	review="${2}"
	export="${3}"

	git checkout -f "${top}"
	tg_update

	# "--short" for when we display the result
	old_rev="$(git rev-parse --short "origin/${top}")"
	new_rev="$(git rev-parse --short "${top}")"

	if [ "${old_rev}" = "${new_rev}" ] && [ "${FORCE}" != "1" ]; then
		printinfo "No new modification, no push"
		return 0
	fi

	tg push

	echo -e "${COLOR_BLUE}"
	printf "New patches for %s:\n" "${top}"
	git log --format="- %h: %s" --reverse --no-merges "${old_rev}..${new_rev}" | \
		grep -v -e "^- \S\+ tg " -e "^- \S\+ tg: " || true

	printf "%sResults: %s..%s (%s)\n" "- " "${old_rev}" "${new_rev}" "${export}"
	echo -e "${COLOR_RESET}"

	print "Publish ${export} and tag (${DATE})? (Y/n)"
	read -n 1 -r
	echo
	if [[ $REPLY =~ ^[Nn]$ ]]; then
		return 0
	fi

	tg_for_review "${top}" "${review}"
	tg_export "${top}" "${export}"
}

if [ -n "${TG_TOP}" ]; then
	git checkout "${TG_TOP}"
	tg_update

	exit 0
fi

DATE=$(date --utc +%Y%m%dT%H%M%S)
publish "${TG_TOPIC_TOP_NET_NEXT}" "${TG_FOR_REVIEW_NET_NEXT}" "${TG_EXPORT_NET_NEXT}"
publish "${TG_TOPIC_TOP_NET}" "${TG_FOR_REVIEW_NET}" "${TG_EXPORT_NET}"

git checkout -f "${TG_TOPIC_TOP_NET_NEXT}"
