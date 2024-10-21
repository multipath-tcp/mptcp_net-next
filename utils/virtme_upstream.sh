#! /bin/bash

exit_trap() {
   # shellcheck disable=SC2317 # trap
   if [ -f .virtme-exec-run-old ]; then
      mv .virtme-exec-run-old .virtme-exec-run
   fi
}

is_stable() {
   [ "$(awk '/^SUBLEVEL = / { print $3; exit }' Makefile)" != 0 ]
}

is_net() {
   [ "$(b4 prep --show-info prefixes 2>/dev/null)" = "net" ]
}

if [ -f .virtme-exec-run ]; then
   mv .virtme-exec-run .virtme-exec-run-old
fi

trap 'exit_trap' EXIT

if is_stable || is_net; then
   PACKETDRILL_STABLE=1
else
   PACKETDRILL_STABLE=0
fi

INPUT_BUILD_SKIP_PERF=1 \
   VIRTME_PACKETDRILL_STABLE=${PACKETDRILL_STABLE} \
   INPUT_SELFTESTS_MPTCP_LIB_OVERRIDE_FLAKY=0 \
   "./${VIRTME_SH:-.virtme.sh}" "${@:-auto-all}"
