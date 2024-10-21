#! /bin/bash

exit_trap() {
   # shellcheck disable=SC2317 # trap
   if [ -f .virtme-exec-run-old ]; then
      mv .virtme-exec-run-old .virtme-exec-run
   fi
}

if [ -f .virtme-exec-run ]; then
   mv .virtme-exec-run .virtme-exec-run-old
fi

is_stable() { local prefix sublevel
   prefix=$(b4 prep --show-info prefixes 2>/dev/null)
   sublevel=$(awk '/^SUBLEVEL = / { print $3; exit }' Makefile)
   if [ "${prefix}" = "net" ] || [[ "${prefix}" = [0-9]"."[0-9]* ]] || [ "${sublevel}" != 0 ]; then
      echo 1
   else
      echo 0
   fi
}

trap 'exit_trap' EXIT

INPUT_BUILD_SKIP_PERF=1 \
   VIRTME_PACKETDRILL_STABLE=$(is_stable) \
   INPUT_SELFTESTS_MPTCP_LIB_OVERRIDE_FLAKY=0 \
   "./${VIRTME_SH:-.virtme.sh}" "${@:-expect-all}"

