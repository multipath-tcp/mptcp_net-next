#!/bin/bash -e

SUBJECT="${*}"

[ -n "${SUBJECT}" ]

pwclient list -a no -f "%{id}==%{state}@@%{name}##" | \
	grep -v -e "==Accepted@@" -e "==Superseded@@" -e "==Deferred@@" -e "==Mainlined@@" -e "==Handled Elsewhere@@" | \
	sed "s/@@\[.*\] /@@/g" | \
	grep --fixed-strings -e "@@${SUBJECT}##" -e "@@${SUBJECT}.##" | \
	cut -d= -f1 | \
	sort -nr
