#!/bin/bash -ex

# Patchwork on kernel.org has extra states
git config --local pw.states \
	new,under-review,accepted,rejected,rfc,not-applicable,changes-requested,awaiting-upstream,superseded,deferred,mainlined,queued,needs_ack

git-pw patch list \
	--limit 250 \
	--state Deferred \
	--state Mainlined \
	--state Accepted \
	--state Superseded \
	--state Rejected \
	-f simple \
	-c ID | \
		tail -n +3 | \
		xargs -r git-pw patch update --archived true

git-pw patch list \
	--limit 250 \
	--state New \
	-f simple \
	-c ID | \
		tail -n +3 | \
		xargs -r git-pw patch update --state needs_ack
