#! /bin/bash
#
# cocci_cc - send cover letter to all mailing lists referenced in a patch series
# intended to be used as 'git send-email --cc-cmd=cocci_cc ...'
# done by Wolfram Sang in 2012-14, version 20140204 - WTFPLv2

shopt -s extglob
cd "$(git rev-parse --show-toplevel)" > /dev/null || exit 1

args=()
# get_maintainer.pl only accepts args without attached parameters
while true; do
    if [[ "${1}" == "--"* ]]; then
        args+=("${1}")
        shift
    else
        break
    fi
done

patch="${1}"
name="$(basename "${patch}")"
num="${name%%-*}"
prefix=""

if [[ "${num}" == "v"* ]]; then
    prefix="${num}-"
    num="$(echo "${name}" | cut -d- -f2)"
fi

if [ "${num}" = "0000" ]; then
    dir="${patch%/*}"
    pre="${dir}/${prefix}"
    for f in "${pre}"*.patch; do
        fname="${f##"${pre}"}"
        if [ "${fname%%-*}" = "0000" ]; then
            continue
        fi
        scripts/get_maintainer.pl "${args[@]}" "${f}"
    done | sort -u
else
    scripts/get_maintainer.pl "${args[@]}" "${patch}"
fi
