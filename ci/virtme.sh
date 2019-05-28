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

SELFTESTS_DIR="tools/testing/selftests/net/mptcp"

"${VIRTME_CONFIGKERNEL}" --arch=x86_64 --defconfig

# Extra options are needed for MPTCP kselftests
echo | scripts/config -e MPTCP -e VETH

make -j"$(nproc)" -l"$(nproc)"
make -j"$(nproc)" -l"$(nproc)" headers_install

OUTPUT_SCRIPT=$(mktemp --tmpdir="${PWD}")
mkdir -p "${VIRTME_SCRIPT_DIR}"
cat <<EOF > "${VIRTME_SCRIPT}"
#! /bin/bash -x
make -C tools/testing/selftests TARGETS=net/mptcp run_tests | \
        tee "${OUTPUT_SCRIPT}"
# to avoid leaving files owned by root
find . -user root -exec rm -rf "{}" \;
EOF

chmod +x "${VIRTME_SCRIPT}"

# allow to launch anything else
if [ "${1}" = "manual" ]; then
        sudo "${VIRTME_RUN}" "${VIRTME_RUN_OPTS[@]}"
        exit
fi

trap 'rm -f "${OUTPUT_SCRIPT}"' EXIT

# for an unknown reason, we cannot use "--script-sh", qemu is not started, no
# debug. As a workaround, we wait for 10 seconds before launching the script
# then we stop.
{ sleep 10; echo "${VIRTME_SCRIPT}"; echo /usr/lib/klibc/bin/poweroff; } | \
        sudo "${VIRTME_RUN}" "${VIRTME_RUN_OPTS[@]}"

if grep -q "^ok [0-9]\+ selftests: mptcp: mptcp_connect\.sh$" "${OUTPUT_SCRIPT}"; then
        echo "Selftests OK"
        exit 0
else
        echo "Error when launching selftests"
        tail -n 20 "${OUTPUT_SCRIPT}"
        exit 1
fi
