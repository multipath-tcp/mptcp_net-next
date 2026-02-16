#! /bin/bash -e

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

TG_TOP="${TG_TOP:-}"
TG_UPSTREAM_RANGE="${TG_UPSTREAM_RANGE:-0}"
REMOTE_KORG="${REMOTE_KORG:-mptcp-korg}"

CI_URL="https://github.com/multipath-tcp/mptcp_net-next/commit/SHA/checks"
CI_TAG="=TODO_CI_LINK="
RESULTS_EXPORT_NET_NEXT=""
TAG_EXPORT_NET_NEXT=""

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

tg_export() { local branch_top branch_export tag msg ci sha
	branch_top="${1}"
	branch_export="${2}"
	tag="${3}"
	msg="${4}"

	git checkout -f "${branch_top}"

	tg export --force --notes "${branch_export}"
	git push --force origin "${branch_export}"
	git push --force "${REMOTE_KORG}" "${branch_export}"

	if [ "${TG_NO_TAG}" = "1" ]; then
		return
	fi

	sha="$(git rev-parse "${branch_export}")"
	ci="$(printf "%s: %s" "- ${branch_export}" "${CI_URL//SHA/${sha}}")"
	# shellcheck disable=SC2153 # TG_EXPORT_NET_NEXT is defined in .lib.sh
	if [ "${branch_export}" = "${TG_EXPORT_NET_NEXT}" ]; then
		TAG_EXPORT_NET_NEXT="${sha}"
	elif [ -n "${TAG_EXPORT_NET_NEXT}" ]; then
		ci+="$(printf "%s: %s" "\\n- ${TG_EXPORT_NET_NEXT}" "${CI_URL//SHA/${TAG_EXPORT_NET_NEXT}}")"
	fi

	msg="${msg//${CI_TAG}/${ci}}"
	printinfo "${msg}"
	if ! wl-copy <<< "$(echo -e "${msg}")" 2>/dev/null; then
		print "Continue?"
		read -r
	fi

	# send a tag to Github to keep previous commits: we might have refs to them
	git tag "${tag}" "${branch_export}"
	git push origin "${tag}"
}

publish() { local top review branch_export old_rev new_rev tag top_txt results msg=""
	top="${1}"
	review="${2}"
	branch_export="${3}"
	tag="${branch_export}/${DATE}"

	git checkout -f "${top}"
	tg_update tg_up_conflicts

	# "--short" for when we display the result
	old_rev="$(git rev-parse --short "origin/${top}")"
	new_rev="$(git rev-parse --short "${top}")"

	if [ "${old_rev}" = "${new_rev}" ] && [ "${FORCE}" != "1" ]; then
		printinfo "No new modification, no push"
		return 0
	fi

	tg push

	top_txt="${top}"
	if [ "${top}" = "${TG_TOPIC_TOP_NET}" ]; then
		top_txt="${top_txt} and ${TG_TOPIC_TOP_NET_NEXT}"
	fi
	msg+="$(printf "New patches for %s:%s" "${top_txt}" "\\n")"
	msg+="$(git log --format="- %h: %s" --reverse --no-merges "${old_rev}..${new_rev}" | \
		grep -v -e "^- \S\+ tg " -e "^- \S\+ tg: " || true)"

	results="- Results: ${old_rev}..${new_rev} (${branch_export})"
	msg+="$(printf "%s" "\\n${results}")"

	if [ "${branch_export}" = "${TG_EXPORT_NET_NEXT}" ]; then
		RESULTS_EXPORT_NET_NEXT="${results}"
	elif [ -n "${RESULTS_EXPORT_NET_NEXT}" ]; then
		msg+="$(printf "%s" "\\n${RESULTS_EXPORT_NET_NEXT}")"
	fi

	msg+="$(printf "\\n\\nTests are now in progress:\\n\\n%s\\n\\n" "${CI_TAG}")"
	printinfo "${msg}"

	print "Publish ${branch_export} and tag (${tag})? (Y/n)"
	read -n 1 -r
	echo
	if [[ $REPLY =~ ^[Nn]$ ]]; then
		return 0
	fi

	tg_for_review "${top}" "${review}"
	tg_export "${top}" "${branch_export}" "${tag}" "${msg}"
}

# $1: top
sync_export() { local top branch_export old_rev new_rev korg_rev
	top="${1}"

	if [ "${top}" = "${TG_TOPIC_TOP_NET}" ]; then
		branch_export="${TG_EXPORT_NET}"
	elif [ "${top}" = "${TG_TOPIC_TOP_NET_NEXT}" ]; then
		branch_export="${TG_EXPORT_NET_NEXT}"
	else
		printinfo "No sync export (top=${top})"
		return 0
	fi

	git fetch origin "${branch_export}"
	new_rev="$(git rev-parse "origin/${branch_export}")"
	korg_rev="$(git rev-parse "${REMOTE_KORG}/${branch_export}")"

	if [ "${korg_rev}" = "${new_rev}" ]; then
		printinfo "No new modification, no sync"
		return 0
	fi

	printinfo "Pushing to korg (remote=${REMOTE_KORG})"
	git branch -f "${branch_export}" "${new_rev}"

	if ! git push -f "${REMOTE_KORG}" "${branch_export}"; then
		printerr "Unable to push to korg, continuing"
	fi
}

if [ -n "${TG_TOP}" ]; then
	git checkout "${TG_TOP}"
	tg_update tg_up_conflicts
	sync_export "${TG_TOP}"

	exit 0
fi

DATE=$(date --utc +%Y%m%dT%H%M%S)
publish "${TG_TOPIC_TOP_NET_NEXT}" "${TG_FOR_REVIEW_NET_NEXT}" "${TG_EXPORT_NET_NEXT}"
publish "${TG_TOPIC_TOP_NET}" "${TG_FOR_REVIEW_NET}" "${TG_EXPORT_NET}"

git checkout -f "${TG_TOPIC_TOP_NET_NEXT}"
