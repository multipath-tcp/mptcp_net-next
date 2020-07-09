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

VIRTME_SCRIPT="${VIRTME_SCRIPT_DIR}/tests.sh"
VIRTME_SCRIPT_END="__VIRTME_END__"
VIRTME_EXPECT_TIMEOUT="900"
VIRTME_RUN_SCRIPT="${VIRTME_SCRIPT_DIR}/virtme.sh"
VIRTME_RUN_EXPECT="${VIRTME_SCRIPT_DIR}/virtme.expect"

KCONFIG_EXTRA_CHECKS=(-e KASAN -e KASAN_OUTLINE -d TEST_KASAN
                      -e PROVE_LOCKING -e DEBUG_LOCKDEP
                      -e PREEMPT -e DEBUG_PREEMPT
                      -e DEBUG_SLAVE -e DEBUG_PAGEALLOC -e DEBUG_MUTEXES -e DEBUG_SPINLOCK -e DEBUG_ATOMIC_SLEEP
                      -e PROVE_RCU -e DEBUG_OBJECTS_RCU_HEAD)

# results for the CI
RESULTS_DIR_BASE="${PWD}/${VIRTME_SCRIPT_DIR}/results"
RESULTS_DIR=

# tmp files
OUTPUT_VIRTME=

EXIT_STATUS=0

# $@: extra kconfig
gen_kconfig() { local kconfig
        # Extra options are needed for MPTCP kselftests
        kconfig=(-e MPTCP -e MPTCP_IPV6 -e VETH -e NET_SCH_NETEM -e INET_DIAG)
        # Extra options needed for MPTCP KUnit tests
        kconfig+=(-m KUNIT -e KUNIT_DEBUGFS -m MPTCP_KUNIT_TESTS)
        # Extra options to avoid questions
        kconfig+=(-e INET_UDP_DIAG -e INET_RAW_DIAG -e INET_DIAG_DESTROY \
                  -d KUNIT_TEST -d KUNIT_EXAMPLE_TEST \
                  -d EXT4_KUNIT_TESTS -d SYSCTL_KUNIT_TEST -d LIST_KUNIT_TEST \
                  -d LINEAR_RANGES_TEST -d KUNIT_ALL_TESTS)
        # Extra options needed for packetdrill
        # note: we still need SHA1 for fallback tests with v0
        kconfig+=(-e TUN -e CRYPTO_USER_API_HASH -e CRYPTO_SHA1)
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

prepare() { local old_pwd
        old_pwd="${PWD}"

        OUTPUT_VIRTME=$(get_tmp_file_rm_previous "${OUTPUT_VIRTME}")
        RESULTS_DIR="${RESULTS_DIR_BASE}/$(git rev-parse --short HEAD)/${1:-}"

        local kunit_tap="${RESULTS_DIR}/kunit.tap"
        local selftests_tap="${RESULTS_DIR}/selftests.tap"
        local mptcp_connect_mmap_tap="${RESULTS_DIR}/mptcp_connect_mmap.tap"
        local packetdrill_mpc_tap="${RESULTS_DIR}/packetdrill_mpc.tap"
        local packetdrill_dss_tap="${RESULTS_DIR}/packetdrill_dss.tap"

        # make sure we have the last stable tests
        cd /opt/packetdrill/
        sudo git fetch origin
        sudo git checkout -f "origin/${PACKETDRILL_GIT_BRANCH}"
        cd gtests/net/packetdrill/
        sudo ./configure
        sudo make
        cd "${old_pwd}"

        rm -rf "${RESULTS_DIR}"
        mkdir -p "${VIRTME_SCRIPT_DIR}" "${RESULTS_DIR}"
        cat <<EOF > "${VIRTME_SCRIPT}"
#! /bin/bash -x

TAP_PREFIX="${PWD}/tools/testing/selftests/kselftest/prefix.pl"

# \$1: file ; \$2+: commands
tap() { local out fname
        out="\${1}"
        fname="\$(basename \${out})"
        shift

        echo "TAP version 13" > "\${out}"
        echo "1..1" >> "\${out}"
        {
                if "\${@}" 2>&1; then
                        echo "ok 1 test: \${fname}" >> "\${out}"
                else
                        echo "not ok 1 test: \${fname} # exit=\${?}" >> "\${out}"
                fi
        } | "\${TAP_PREFIX}" | tee -a "\${out}"
}

# kunit
{
        insmod ./lib/kunit/kunit.ko

        echo "TAP version 14"
        echo "1..$(echo net/mptcp/*_test.ko | wc -w)"

        for ko in net/mptcp/*_test.ko; do
                insmod "\${ko}"

                kunit="\${ko:10:-8}"
                kunit="\${kunit//_/-}"
                cat /sys/kernel/debug/kunit/\${kunit}/results
        done
} > "${kunit_tap}"

# selftests
make -C tools/testing/selftests TARGETS=net/mptcp run_tests | \
        grep -v -e "^make" -e "^\\s" | \
        tee "${selftests_tap}"

cd tools/testing/selftests/net/mptcp
tap "${mptcp_connect_mmap_tap}" ./mptcp_connect.sh -m mmap

# TODO: mptcp_connect.sh with -R ; -S

# packetdrill
cd /opt/packetdrill/gtests/net/
export PYTHONUNBUFFERED=1
tap "${packetdrill_mpc_tap}" ./packetdrill/run_all.py -l -v mptcp/mp_capable
tap "${packetdrill_dss_tap}" ./packetdrill/run_all.py -l -v mptcp/dss

# end
echo "${VIRTME_SCRIPT_END}"
EOF
        chmod +x "${VIRTME_SCRIPT}"

        trap 'rm -f "${OUTPUT_VIRTME}"' EXIT
}

run() {
        sudo "${VIRTME_RUN}" "${VIRTME_RUN_OPTS[@]}"
}

run_expect() {
        cat <<EOF > "${VIRTME_RUN_SCRIPT}"
#! /bin/bash -x
sudo "${VIRTME_RUN}" ${VIRTME_RUN_OPTS[@]} 2>&1 | tr -d '\r'
EOF
        chmod +x "${VIRTME_RUN_SCRIPT}"

        cat <<EOF > "${VIRTME_RUN_EXPECT}"
#!/usr/bin/expect -f

set timeout "${VIRTME_EXPECT_TIMEOUT}"

spawn "${VIRTME_RUN_SCRIPT}"

expect "virtme-init: console is ttyS0\r"
send -- "stdbuf -oL ${VIRTME_SCRIPT}\r"

expect "${VIRTME_SCRIPT_END}\r"
send -- "/usr/lib/klibc/bin/poweroff\r"

expect eof
EOF
        chmod +x "${VIRTME_RUN_EXPECT}"

        # for an unknown reason, we cannot use "--script-sh", qemu is not
        # started, no debug. As a workaround, we use expect.
        "${VIRTME_RUN_EXPECT}" | tee "${OUTPUT_VIRTME}"
}

clean() {
        # to be able to read files from users and not to be rm by the clean step
        sudo chown -R "$(id -u):$(id -g)" "${RESULTS_DIR}"

        # to avoid leaving files owned by root
        sudo find . -user root -exec rm -vrf "{}" \; || true
}

# $@: args for kconfig
analyse() {
        # look for crashes/warnings
        if grep -C 30 "Call Trace:" "${OUTPUT_VIRTME}"; then
                echo "Call Trace found (additional kconfig: '${*}')"
                # exit directly, that's bad
                exit 1
        fi

        if ! grep -q "${VIRTME_SCRIPT_END}" "${OUTPUT_VIRTME}"; then
                echo "Timeout (additional kconfig: '${*}')"
                # exit directly, that's bad
                exit 1
        fi

        if grep -r "^not ok " "${RESULTS_DIR}"; then
                EXIT_STATUS=42
        fi
}

# $@: args for kconfig
go_manual() {
        gen_kconfig "${@}"
        build
        prepare
        run
        clean
        rm -rf "${RESULTS_DIR}"
}

# $1: mode ; $2+: args for kconfig
go_expect() { local mode
        mode="${1}"
        shift

        gen_kconfig "${@}"
        build
        prepare "${mode}"
        run_expect
        clean
        analyse "${@}"
}


# allow to launch anything else
if [ "${1}" = "manual" ]; then
        shift
        go_manual "${@}"
else
        # first with the minimum because configs like KASAN slow down the
        # tests execution, it might hide bugs
        go_expect "normal" "${@}"
        go_expect "debug" "${KCONFIG_EXTRA_CHECKS[@]}" "${@}"
fi

exit "${EXIT_STATUS}"
