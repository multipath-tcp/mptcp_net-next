#! /bin/bash

if [ -f .virtme-exec-run ]; then
   mv .virtme-exec-run .virtme-exec-run-old
fi

is_stable() {
   if [ "$(b4 prep --show-info 2>/dev/null | awk '/^prefixes: / { print $2 }')" = "net" ]; then
      echo 1
   else
      echo 0
   fi
}

VIRTME_PACKETDRILL_STABLE=$(is_stable) ./.virtme.sh expect-all

if [ -f .virtme-exec-run-old ]; then
   mv .virtme-exec-run-old .virtme-exec-run
fi
