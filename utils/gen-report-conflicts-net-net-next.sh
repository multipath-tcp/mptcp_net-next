#! /bin/bash -e

NET="${1:?}"
NEXT="${2:?}"
FIX="${3:?}"
shift 3

long() {
	git rev-parse "${@}"
}

short() {
	git rev-parse --short "${@}"
}

desc() {
	git show -s --format='%h ("%s")' "${@}"
}

diff() {
	git diff ${1} ${1}^ ${1}^2 "${@:2}"
}

cat <<EOF
Hello

(...)

FYI, we got a small conflict when merging 'net' in 'net-next' in the
MPTCP tree due to this patch applied in 'net':

  $(desc "${NET}")

and this one from 'net-next':

  $(desc "${NEXT}")

----- Generic Message -----
The best is to avoid conflicts between 'net' and 'net-next' trees but if
they cannot be avoided when preparing patches, a note about how to fix
them is much appreciated.

The conflict has been resolved on our side[1] and the resolution we
suggest is attached to this email. Please report any issues linked to
this conflict resolution as it might be used by others. If you worked on
the mentioned patches, don't hesitate to ACK this conflict resolution.
---------------------------

Regarding this conflict, (...)

Cheers,
Matt

[1] https://github.com/multipath-tcp/mptcp_net-next/commit/$(short "${FIX}")
EOF

PATCH="$(long "${FIX}").patch"
diff "${FIX}" "${@}" > "${PATCH}"
echo -e "\n\t=== Please include ${PATCH} in the email. ===\n"
echo -e "\n\t=== Please append the subject with 'manual merge'. ===\n"
