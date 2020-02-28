#! /bin/bash
#
# The goal is to launch MPTCP kernel selftests
#
# Arguments:
#   - "manual": to have a console in the VM. Additional args are for the kconfig
#   - args we pass to kernel's "scripts/config" script.

# We should manage all errors in this script
set -e

VIRTME_PATH="/opt/virtme"
VIRTME_CONFIGKERNEL="${VIRTME_PATH}/virtme-configkernel"
VIRTME_RUN="${VIRTME_PATH}/virtme-run"
VIRTME_RUN_OPTS=(--net --balloon --memory 768M --kdir "${PWD}" --mods=none --rwdir "${PWD}" --pwd)

VIRTME_SCRIPT_DIR="patches/virtme"
VIRTME_SCRIPT="${VIRTME_SCRIPT_DIR}/selftests.sh"
VIRTME_SCRIPT_END="__VIRTME_END__"
VIRTME_RUN_SCRIPT="${VIRTME_SCRIPT_DIR}/virtme.sh"
VIRTME_RUN_EXPECT="${VIRTME_SCRIPT_DIR}/virtme.expect"

SELFTESTS_DIR="tools/testing/selftests/net/mptcp"

KCONFIG_EXTRA_CHECKS=(-e KASAN -e KASAN_OUTLINE -d TEST_KASAN
                      -e PROVE_LOCKING -e DEBUG_LOCKDEP
                      -e PREEMPT -e DEBUG_PREEMPT
                      -e DEBUG_SLAVE -e DEBUG_PAGEALLOC -e DEBUG_MUTEXES -e DEBUG_SPINLOCK -e DEBUG_ATOMIC_SLEEP
                      -e PROVE_RCU -e DEBUG_OBJECTS_RCU_HEAD)

# tmp files
OUTPUT_SCRIPT=
OUTPUT_VIRTME=

# $@: extra kconfig
gen_kconfig() { local kconfig
        # Extra options are needed for MPTCP kselftests
        kconfig=(-e MPTCP -e MPTCP_IPV6 -e MPTCP_HMAC_TEST -e VETH -e NET_SCH_NETEM)
        if [ -n "${1}" ]; then
                kconfig+=("${@}")
        fi

        "${VIRTME_CONFIGKERNEL}" --arch=x86_64 --defconfig

        echo | ./scripts/config "${kconfig[@]}"
}

build() {
        make -j"$(nproc)" -l"$(nproc)"
        make -j"$(nproc)" -l"$(nproc)" headers_install
}

# $1 previous file
get_tmp_file_rm_previous() {
        if [ -f "${1}" ]; then
                rm -f "${1}"
        fi

        mktemp --tmpdir="${PWD}"
}

prepare() {
        OUTPUT_SCRIPT=$(get_tmp_file_rm_previous "${OUTPUT_SCRIPT}")
        OUTPUT_VIRTME=$(get_tmp_file_rm_previous "${OUTPUT_VIRTME}")

        mkdir -p "${VIRTME_SCRIPT_DIR}"
        cat <<EOF > "${VIRTME_SCRIPT}"
#! /bin/bash -x
time make -C tools/testing/selftests TARGETS=net/mptcp run_tests | \
        tee "${OUTPUT_SCRIPT}"
# to avoid leaving files owned by root
find . -user root -exec rm -rf "{}" \;
echo "${VIRTME_SCRIPT_END}"
EOF
        chmod +x "${VIRTME_SCRIPT}"

        trap 'rm -f "${OUTPUT_SCRIPT}" "${OUTPUT_VIRTME}"' EXIT
}

run() {
        sudo "${VIRTME_RUN}" "${VIRTME_RUN_OPTS[@]}"
}

run_expect() {
        cat <<EOF > "${VIRTME_RUN_SCRIPT}"
#! /bin/bash -x
sudo "${VIRTME_RUN}" ${VIRTME_RUN_OPTS[@]} 2>&1
EOF
        chmod +x "${VIRTME_RUN_SCRIPT}"

        cat <<EOF > "${VIRTME_RUN_EXPECT}"
#!/usr/bin/expect -f

set timeout 900

spawn "${VIRTME_RUN_SCRIPT}"

expect "virtme-init: console is ttyS0\r"
send -- "${VIRTME_SCRIPT}\r"

expect "${VIRTME_SCRIPT_END}\r"
send -- "/usr/lib/klibc/bin/poweroff\r"

expect eof
EOF
        chmod +x "${VIRTME_RUN_EXPECT}"

        # for an unknown reason, we cannot use "--script-sh", qemu is not
        # started, no debug. As a workaround, we use expect.
        "${VIRTME_RUN_EXPECT}" | tee "${OUTPUT_VIRTME}"
}

# $@: args for kconfig
analyse() {
        echo "Kconfig: ${*}"
        if grep -C 30 "Call Trace:" "${OUTPUT_VIRTME}"; then
                echo "Call Trace found"
                exit 2
        elif grep -q "^ok [0-9]\+ selftests: \S*mptcp: mptcp_connect\.sh$" "${OUTPUT_SCRIPT}"; then
                echo "Selftests OK"
        else
                echo "Error when launching selftests"
                grep -A 9999 "^# selftests: \S*mptcp: mptcp_connect\.sh$" "${OUTPUT_SCRIPT}"
                exit 1
        fi
}

# $@: args for kconfig
go_manual() {
        gen_kconfig "${@}"
        build
        run
}

# $@: args for kconfig
go_expect() {
        gen_kconfig "${@}"
        build
        prepare
        run_expect
        analyse "${@}"
}


# allow to launch anything else
if [ "${1}" = "manual" ]; then
        shift
        go_manual "${@}"
else
        # first with the minimum because configs like KASAN slow down the
        # tests execution, it might hide bugs
        go_expect "${@}"
        go_expect "${KCONFIG_EXTRA_CHECKS[@]}" "${@}"
fi
