#!/bin/bash -ex

case "${1}" in
	"net" | "net-next" | "bpf" | "bpf-next" | "iproute2" | "iproute2-next")
		TARGET="${1}"
		shift
		;;
	*)
		echo "Unknown target '${1}'"
		exit 1
		;;
esac

git format-patch --subject-prefix="PATCH ${TARGET}" -o "patches/$(git rev-parse --abbrev-ref HEAD)" --notes "${@}"
