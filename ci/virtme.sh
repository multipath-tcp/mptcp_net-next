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
OUTPUT_SELFTESTS=
OUTPUT_VIRTME=
OUTPUT_PACKETDRILL=

CONNECT_MMAP_BEGIN="__CONNECT_MMAP_BEGIN__"
CONNECT_MMAP_ERROR="__CONNECT_MMAP_ERROR__"

# $@: extra kconfig
gen_kconfig() { local kconfig
        # Extra options are needed for MPTCP kselftests
        kconfig=(-e MPTCP -e MPTCP_IPV6 -e VETH -e NET_SCH_NETEM)
        # Extra options needed for MPTCP KUnit tests
        kconfig+=(-m KUNIT -e KUNIT_DEBUGFS \
                  -d KUNIT_TEST -d KUNIT_EXAMPLE_TEST \
                  -d EXT4_KUNIT_TESTS -d SYSCTL_KUNIT_TEST -d LIST_KUNIT_TEST \
                  -d LINEAR_RANGES_TEST -d KUNIT_ALL_TESTS \
                  -m MPTCP_KUNIT_TESTS)
        # Extra options needed for packetdrill
        kconfig+=(-e TUN -e CRYPTO_USER_API_HASH)
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
        OUTPUT_SELFTESTS=$(get_tmp_file_rm_previous "${OUTPUT_SELFTESTS}")
        OUTPUT_VIRTME=$(get_tmp_file_rm_previous "${OUTPUT_VIRTME}")
        OUTPUT_PACKETDRILL=$(get_tmp_file_rm_previous "${OUTPUT_PACKETDRILL}")

        # make sure we have the last stable tests
        cd /opt/packetdrill/
        sudo git fetch origin
        sudo git checkout -f "origin/${PACKETDRILL_GIT_BRANCH}"
        cd gtests/net/packetdrill/
        sudo ./configure
        sudo make
        cd "${old_pwd}"

        mkdir -p "${VIRTME_SCRIPT_DIR}"
        cat <<EOF > "${VIRTME_SCRIPT}"
#! /bin/bash -x

# kunit
insmod ./lib/kunit/kunit.ko
for ko in net/mptcp/*_test.ko; do
	insmod "\${ko}"
done

# selftests
time make -C tools/testing/selftests TARGETS=net/mptcp run_tests | \
        tee "${OUTPUT_SELFTESTS}"

cd tools/testing/selftests/net/mptcp
echo "${CONNECT_MMAP_BEGIN}" >> "${OUTPUT_SELFTESTS}"
{ ./mptcp_connect.sh -m mmap 2>&1 || echo "${CONNECT_MMAP_ERROR}" >> "${OUTPUT_SELFTESTS}"; } | \
        tee -a "${OUTPUT_SELFTESTS}"

# TODO: mptcp_connect.sh with -R ; -S

# packetdrill
cd /opt/packetdrill/gtests/net/
./packetdrill/run_all.py -l -v mptcp/mp_capable 2>&1 | tee "${OUTPUT_PACKETDRILL}"
./packetdrill/run_all.py -l -v mptcp/dss 2>&1 | tee -a "${OUTPUT_PACKETDRILL}"

# end
echo "${VIRTME_SCRIPT_END}"
EOF
        chmod +x "${VIRTME_SCRIPT}"

        trap 'rm -f "${OUTPUT_SELFTESTS}" "${OUTPUT_VIRTME}" "${OUTPUT_PACKETDRILL}"' EXIT
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

clean_expect() {
        # to avoid leaving files owned by root
        find . -user root -exec rm -rf "{}" \; || true
}

# $@: args for kconfig
analyse() {
        echo "Kconfig: ${*}"

        # look for crashes/warnings
        if grep -C 30 "Call Trace:" "${OUTPUT_VIRTME}"; then
                echo "Call Trace found"
                # exit directly, that's bad
                exit 2
        fi

	# KUnit tests
        if ! grep -q "\] ok 1 - mptcp-crypto" "${OUTPUT_VIRTME}"; then
                echo "KUnit Crypto tests failed"
                grep -B 10 "mptcp-crypto" "${OUTPUT_VIRTME}"
                exit 2
        fi
        if ! grep -q "\] ok 2 - mptcp-token" "${OUTPUT_VIRTME}"; then
                echo "KUnit Token tests failed"
                grep -B 10 "mptcp-token" "${OUTPUT_VIRTME}"
                exit 2
        fi

        # check selftests results
        if grep -q "^not ok [0-9]\+ selftests: net/mptcp: " "${OUTPUT_SELFTESTS}"; then
                echo "Error when launching selftests"
                local not_ok
                for not_ok in $(grep "^not ok [0-9]\+ selftests: net/mptcp: *" "${OUTPUT_SELFTESTS}" | \
                                sed "s/.*net\/mptcp: \(\S\+\).*/\1/"); do
                        sed -n "/^# selftests: net\/mptcp: ${not_ok}$/,/^not ok [0-9]\+ selftests: net\/mptcp: ${not_ok} #/p" "${OUTPUT_SELFTESTS}"
                done
                exit 1
        else
                echo "Selftests OK"
        fi

        if grep -q "${CONNECT_MMAP_ERROR}" "${OUTPUT_SELFTESTS}"; then
                echo "Error with mptcp_connect.sh mmap"
                sed -n "/^${CONNECT_MMAP_BEGIN}$/,/^${CONNECT_MMAP_ERROR}$/p" "${OUTPUT_SELFTESTS}"
                exit 1
        else
                echo "mptcp_connect.sh mmap OK"
        fi

        # check packetdrill results
        if grep "^Ran " "${OUTPUT_PACKETDRILL}" | grep -vq " 0 failing"; then
                echo "Error when launching packetdrill"
                cat "${OUTPUT_PACKETDRILL}"
                exit 3
        else
                echo "Packetdrill OK"
        fi
}

# $@: args for kconfig
go_manual() {
        gen_kconfig "${@}"
        build
        prepare
        run
        clean_expect
}

# $@: args for kconfig
go_expect() {
        gen_kconfig "${@}"
        build
        prepare
        run_expect
        clean_expect
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
