#!/bin/bash -e

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

TARGET="${TARGET}" ./.gen-patch.sh "${@:--1}"
