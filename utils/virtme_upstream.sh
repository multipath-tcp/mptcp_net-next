#! /bin/bash

is_stable() {
   [ "$(awk '/^SUBLEVEL = / { print $3; exit }' Makefile)" != 0 ]
}

is_net() {
   [ "$(b4 prep --show-info prefixes 2>/dev/null)" = "net" ]
}

if is_stable || is_net; then
   SUFFIX=$(make kernelversion | cut -d. -f1-2)
   PACKETDRILL_STABLE=1
else
   SUFFIX=
   PACKETDRILL_STABLE=0
fi

INPUT_BUILD_SKIP_PERF=1 \
   INPUT_VIRTME_EXEC_RUN="${INPUT_VIRTME_EXEC_RUN:-/dev/null}" \
   VIRTME_PACKETDRILL_STABLE=${PACKETDRILL_STABLE} \
   INPUT_SELFTESTS_MPTCP_LIB_OVERRIDE_FLAKY=0 \
   INPUT_BUILD_SUFFIX=${SUFFIX} \
   "./${VIRTME_SH:-.virtme.sh}" "${@:-auto-all}"
