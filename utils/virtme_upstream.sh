#! /bin/bash

: "${DRY_RUN:=0}"

is_stable() {
   [ "${INPUT_STABLE}" = 1 ] ||
      [ -s ".git/BISECT_LOG" ] ||
      [ "$(awk '/^SUBLEVEL = / { print $3; exit }' Makefile)" != 0 ]
}

is_net() {
   [ "$(b4 prep --show-info prefixes 2>/dev/null)" = "net" ]
}

if [ "${DRY_RUN}" = 1 ]; then
   EXEC="echo"
   set -x
else
   EXEC=""
fi

SYZK=0
trap_exit() {
   if [ "${SYZK}" = 1 ]; then
      echo "Restarting syzkaller"
      ${EXEC} systemctl --user start syzkaller || true
   fi
}
trap trap_exit EXIT

CLEAN=0

if systemctl --user is-enabled syzkaller &>/dev/null && systemctl --user is-active syzkaller &>/dev/null; then
   SYZK=1
   echo "Stopping syzkaller..."
   ${EXEC} systemctl --user stop syzkaller
fi

if is_stable || is_net; then
   SUFFIX=$(make kernelversion | cut -d. -f1-2)
   PACKETDRILL_STABLE=1
   is_stable && [[ "${1}" != "vm"* ]] && CLEAN=1
else
   SUFFIX=
   PACKETDRILL_STABLE=0
fi

[ "${DRY_RUN}" = 1 ] && exit

INPUT_BUILD_SKIP_PERF=1 \
   INPUT_VIRTME_EXEC_RUN="${INPUT_VIRTME_EXEC_RUN:-/dev/null}" \
   VIRTME_PACKETDRILL_STABLE=${PACKETDRILL_STABLE} \
   INPUT_SELFTESTS_MPTCP_LIB_OVERRIDE_FLAKY=0 \
   INPUT_CLEAN="${INPUT_CLEAN:-${CLEAN}}" \
   INPUT_BUILD_SUFFIX="${SUFFIX}" \
   INPUT_EXPECT_TIMEOUT=7200 \
   "./${VIRTME_SH:-.virtme.sh}" "${@:-auto-all}"
