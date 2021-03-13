#! /bin/bash -e

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

TG_TOP="${TG_TOP:-t/upstream}"
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


git checkout "${TG_TOP}"
tg_update

if [ "${TG_PUSH}" = 1 ]; then
	OLD_REV="$(git rev-parse --short "origin/${TG_TOP}")"
	NEW_REV="$(git rev-parse --short "${TG_TOP}")"

	tg push

	if [ "${OLD_REV}" = "${NEW_REV}" ]; then
		exit
	fi

	echo -e "${COLOR_BLUE}"
	printf "New patches:\n"
	git log --format="- %h: %s" --reverse --no-merges "${OLD_REV}..${NEW_REV}" | \
		grep -v -e "^- \S\+ tg " -e "^- \S\+ tg: " || true

	printf "%sResults: %s..%s\n" "- " "${OLD_REV}" "${NEW_REV}"
	echo -e "${COLOR_RESET}"
fi
