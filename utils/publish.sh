#! /bin/bash -e

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

TG_FOR_REVIEW="for-review"
TG_EXPORT="export"

TG_TOP="${TG_TOP:-${TG_TOPIC_TOP}}"
TG_PUSH="${TG_PUSH:-1}"
TG_UPSTREAM="${TG_UPSTREAM:-0}"

TG_BOTTOM="net-next"

tg_up_err() {
	printerr "Please fix the conflicts in another terminal." \
	         "End with ./.end-conflict.sh, then press Enter to continue."
	read -r
}

topic_has_been_upstreamed() { local subject="${1}"
	git log \
		--fixed-strings \
		--grep "${subject}" \
		--format="format:==%s==" \
		"${TG_UPSTREAM}..${TG_BOTTOM}" | \
			grep -q --fixed-strings "==${subject}=="
}

tg_up_upstream() { local subject
	if [ "${TG_UPSTREAM}" = "0" ]; then
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

tg_for_review() {
	git branch -f "${TG_FOR_REVIEW}" origin/"${TG_FOR_REVIEW}"
	git checkout -f "${TG_FOR_REVIEW}"
	if ! git merge --no-edit --signoff "${TG_TOP}"; then
		# the only possible conflict would be with the topgit files, manage this
		tg_conflict_files=$(git status --porcelain | grep -E "^DU\\s.top(deps|msg)$")
		if [ -n "${tg_conflict_files}" ]; then
			echo "${tg_conflict_files}" | awk '{ print $2 }' | xargs git rm
			if ! git commit -s --no-edit; then
				printerr "Unexpected other conflicts: ${tg_conflict_files}"
				exit 1
			fi
		else
			printerr "Unexpected conflicts when updating ${TG_FOR_REVIEW}"
			exit 1
		fi
	fi

	git push origin "${TG_FOR_REVIEW}"
	git checkout -f "${TG_TOP}"
}

tg_export() {
	git checkout -f "${TG_TOP}"
	tg export --linearize --force "${TG_EXPORT}"
	git push -f origin "${TG_EXPORT}"
	git checkout -f "${TG_TOP}"
}

tg_tag() { local tag
	tag="${TG_EXPORT}/$(date --utc +%Y%m%dT%H%M%S)"

	git tag "${tag}" "${TG_EXPORT}"
	git push -f origin "${tag}"

	printinfo "Builds and tests are now in progress:\\n"
	printinfo "https://cirrus-ci.com/github/multipath-tcp/mptcp_net-next/${tag}"
	printinfo "https://github.com/multipath-tcp/mptcp_net-next/actions/workflows/build-validation.yml?query=branch:${tag}"
}

tg_export_tag() {
	tg_export

	if [ "${TG_NO_TAG}" != "1" ]; then
		tg_tag
	fi
}


git checkout "${TG_TOP}"
tg_update

if [ "${TG_PUSH}" = 1 ]; then
	OLD_REV="$(git rev-parse --short "origin/${TG_TOP}")"
	NEW_REV="$(git rev-parse --short "${TG_TOP}")"

	if [ "${OLD_REV}" = "${NEW_REV}" ]; then
		printinfo "No new modification, no push"
		exit
	fi

	tg push

	if [ "${TG_TOP}" != "${TG_TOPIC_TOP}" ]; then
		printinfo "Not on ${TG_TOPIC_TOP}, no new tag and summary"
		exit
	fi

	echo -e "${COLOR_BLUE}"
	printf "New patches:\n"
	git log --format="- %h: %s" --reverse --no-merges "${OLD_REV}..${NEW_REV}" | \
		grep -v -e "^- \S\+ tg " -e "^- \S\+ tg: " || true

	printf "%sResults: %s..%s\n" "- " "${OLD_REV}" "${NEW_REV}"
	echo -e "${COLOR_RESET}"

	print "Publish export and tag? (Y/n)"
	read -n 1 -r
	echo
	if [[ $REPLY =~ ^[Nn]$ ]]; then
		exit 0
	fi

	tg_for_review
	tg_export_tag
fi
