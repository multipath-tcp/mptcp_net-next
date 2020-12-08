#! /bin/bash -e

# shellcheck disable=SC1091
# shellcheck source=./lib.sh
source ./.lib.sh

TG_TOP="${TG_TOP:-t/upstream}"
TG_PUSH="${TG_PUSH:-1}"

tg_up_err() {
	printerr "Please fix the conflicts in another terminal." \
	         "End with ./.end-conflict.sh, then press Enter to continue."
	read -r
}

tg_update() {
	if ! tg update; then
		tg_up_err

		while ! tg update --continue; do
			tg_up_err
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
