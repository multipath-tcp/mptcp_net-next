#! /bin/bash -ex

TG_TOP="${TG_TOP:-t/upstream}"
TG_PUSH="${TG_PUSH:-1}"

tg_up_err() {
	echo "Please fix the conflicts in another terminal." \
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

	echo "New patches:"
	git log --format="- %h: %s" --reverse --no-merges "${OLD_REV}..${NEW_REV}" | \
		grep -v -e "^- \S\+ tg " -e "^- \S\+ tg: " || true

	echo "- Results: ${OLD_REV}..${NEW_REV}"
fi
