#! /bin/bash

if [ -f .virtme-exec-run ]; then
   mv .virtme-exec-run .virtme-exec-run-old
fi

is_stable() { local prefix sublevel
   prefix=$(b4 prep --show-info 2>/dev/null | awk '/^prefixes: / { print $2 }')
   sublevel=$(awk '/^SUBLEVEL = / { print $3; exit }' Makefile)
   if [ "${prefix}" = "net" ] || [[ "${prefix}" = [0-9]"."[0-9]* ]] || [ "${sublevel}" != 0 ]; then
      echo 1
   else
      echo 0
   fi
}

./.virtme.sh make -C tools/perf clean

rc=0
VIRTME_PACKETDRILL_STABLE=$(is_stable) ./.virtme.sh "${@:-expect-all}" || rc=${?}

if [ -f .virtme-exec-run-old ]; then
   mv .virtme-exec-run-old .virtme-exec-run
fi

exit ${rc}
