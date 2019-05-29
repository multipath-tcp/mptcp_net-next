#! /bin/bash
#
# The goal is to launch MPTCP kernel selftests

# We should manage all errors in this script
set -e

VIRTME_PATH="/tmp/virtme"
VIRTME_CONFIGKERNEL="${VIRTME_PATH}/virtme-configkernel"
VIRTME_RUN="${VIRTME_PATH}/virtme-run"
VIRTME_RUN_OPTS=(--net --balloon --memory 512M --kdir "${PWD}" --rwdir "${PWD}" --pwd)

VIRTME_SCRIPT_DIR="patches/virtme"
VIRTME_SCRIPT="${VIRTME_SCRIPT_DIR}/selftests.sh"
VIRTME_SCRIPT_END="__VIRTME_END__"
VIRTME_RUN_SCRIPT="${VIRTME_SCRIPT_DIR}/virtme.sh"
VIRTME_RUN_EXPECT="${VIRTME_SCRIPT_DIR}/virtme.expect"

SELFTESTS_DIR="tools/testing/selftests/net/mptcp"

"${VIRTME_CONFIGKERNEL}" --arch=x86_64 --defconfig

# Extra options are needed for MPTCP kselftests and debug
echo | scripts/config -e MPTCP -e VETH -e NET_SCH_NETEM \
                      -e KASAN -e KASAN_OUTLINE -d TEST_KASAN \
                      -e PROVE_LOCKING -d DEBUG_LOCKDEP

make -j"$(nproc)" -l"$(nproc)"
make -j"$(nproc)" -l"$(nproc)" headers_install

OUTPUT_SCRIPT=$(mktemp --tmpdir="${PWD}")
OUTPUT_VIRTME=$(mktemp --tmpdir="${PWD}")

mkdir -p "${VIRTME_SCRIPT_DIR}"
cat <<EOF > "${VIRTME_SCRIPT}"
#! /bin/bash -x
make -C tools/testing/selftests TARGETS=net/mptcp run_tests | \
        tee "${OUTPUT_SCRIPT}"
# to avoid leaving files owned by root
find . -user root -exec rm -rf "{}" \;
echo "${VIRTME_SCRIPT_END}"
EOF
chmod +x "${VIRTME_SCRIPT}"

# allow to launch anything else
if [ "${1}" = "manual" ]; then
        sudo "${VIRTME_RUN}" "${VIRTME_RUN_OPTS[@]}"
        exit
fi

trap 'rm -f "${OUTPUT_SCRIPT}" "${OUTPUT_VIRTME}"' EXIT

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

# for an unknown reason, we cannot use "--script-sh", qemu is not started, no
# debug. As a workaround, we use expect
"${VIRTME_RUN_EXPECT}" | tee "${OUTPUT_VIRTME}"

if grep -C 30 "Call Trace:" "${OUTPUT_VIRTME}"; then
        echo "Call Trace found"
        exit 2
elif grep -q "^ok [0-9]\+ selftests: mptcp: mptcp_connect\.sh$" "${OUTPUT_SCRIPT}"; then
        echo "Selftests OK"
        exit 0
else
        echo "Error when launching selftests"
        grep -A 9999 "^# selftests: mptcp: mptcp_connect\.sh$" "${OUTPUT_SCRIPT}"
        exit 1
fi
