#! /bin/bash
#
# Generate a Dockerfile, build it and run virtme.sh script

# We should manage all errors in this script
set -e

SCRIPT="${1:-./virtme.sh}"
if ! test -f "${SCRIPT}"; then
    echo "Unable to execute ${SCRIPT} from ${PWD}"
    exit 1
fi
shift
SCRIPT_OPTS=("${@}")

DOCKER_NAME="virtme"
DOCKER_DIR=$(dirname "${0}")
if [ "${1}" = "manual" ]; then
        DOCKER_EXTRA_ARGS="-it"
fi

VIRTME_GIT_URL="git://git.kernel.org/pub/scm/utils/kernel/virtme/virtme.git"

DOCKERFILE=$(mktemp --tmpdir="${DOCKER_DIR}")
trap 'rm -f "${DOCKERFILE}"' EXIT

cat <<EOF > "${DOCKERFILE}"
FROM ubuntu:latest

# Use the same rights as the launcher
RUN mkdir -p "$(dirname "${HOME}")" && \
    useradd -ms /bin/bash -u "${UID}" -U "${USER}" -d "${HOME}"

# dependencies for the script
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends \
                    build-essential libncurses5-dev gcc libssl-dev bc bison \
                    libelf-dev flex git curl tar hashalot qemu-kvm sudo expect \
                    python3 python3-pkg-resources busybox iproute2 tcpdump \
                    iputils-ping ethtool klibc-utils rsync && \
    apt-get clean

# virtme and sudo rights (for kvm)
RUN cd /tmp && \
    git clone "${VIRTME_GIT_URL}" && \
    usermod -a -G sudo "${USER}" && \
    echo "${USER} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# switch to the current user and current dir
USER ${USER}
VOLUME ${PWD}
WORKDIR ${PWD}
EOF

docker build -t "${DOCKER_NAME}" -f "${DOCKERFILE}" "${DOCKER_DIR}"

# extra rights needed for KVM
sudo docker run \
    -v "${PWD}:${PWD}" \
    --privileged \
    --rm ${DOCKER_EXTRA_ARGS:+"${DOCKER_EXTRA_ARGS}"} \
    "${DOCKER_NAME}" \
    bash "-${-}" "${SCRIPT}" "${SCRIPT_OPTS[@]}"
