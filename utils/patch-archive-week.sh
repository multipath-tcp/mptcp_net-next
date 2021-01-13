#!/bin/bash -ex

git-pw patch list \
	--limit 250 \
	--state Deferred \
	--state Accepted \
	--state Superseded \
	--state Rejected \
	-f simple \
	-c ID | \
		tail -n +3 | \
		xargs -r git-pw patch update --archived true

# Patchwork on ozlab has an extra state
git config --local pw.states \
	new,under-review,accepted,rejected,rfc,not-applicable,changes-requested,awaiting-upstream,superseded,deferred,needs-review-ack

git-pw patch list \
	--limit 250 \
	--state New \
	-f simple \
	-c ID | \
		tail -n +3 | \
		xargs -r git-pw patch update --state needs-review-ack
