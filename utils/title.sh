#! /bin/bash
git show "${1:-HEAD}:.topmsg" | head -n2  | grep "^Subject: " | cut -d\] -f2- | sed "s/^ //"
