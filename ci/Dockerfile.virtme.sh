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
VIRTME_GIT_SHA="a2223d11b58097b0cbb8eeacf66b17699ddada7f"
PACKETDRILL_GIT_URL="https://github.com/multipath-tcp/packetdrill.git"
PACKETDRILL_GIT_BRANCH="mptcp-net-next"

DOCKERFILE=$(mktemp --tmpdir="${DOCKER_DIR}")
trap 'rm -f "${DOCKERFILE}"' EXIT

cat <<EOF > "${DOCKERFILE}"
FROM ubuntu:bionic

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
                    iputils-ping ethtool klibc-utils rsync ccache \
                    ca-certificates gnupg2 net-tools && \
    apt-get clean

# CLang dev for BPF selftests (curl required)
RUN echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic main" > /etc/apt/sources.list.d/clang.list && \
    curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends \
                    clang lld llvm libcap-dev && \
    apt-get clean

# virtme
RUN cd /opt && \
    git clone "${VIRTME_GIT_URL}" && \
    cd virtme && \
    git checkout "${VIRTME_GIT_SHA}"

# packetdrill
ENV PACKETDRILL_GIT_BRANCH "${PACKETDRILL_GIT_BRANCH}"
RUN cd /opt && \
    git clone "${PACKETDRILL_GIT_URL}" && \
    cd packetdrill && \
        git checkout "${PACKETDRILL_GIT_BRANCH}" && \
        cd gtests/net/packetdrill/ && \
            ./configure && \
            make

# sudo rights (for kvm)
RUN usermod -a -G sudo "${USER}" && \
    echo "${USER} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# CCache for quicker builds with default colours
# Note: use 'ccache -M xG' to increase max size, default is 5GB
ENV PATH /usr/lib/ccache:\${PATH}
ENV CCACHE_COMPRESS true
ENV GCC_COLORS error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01

# switch to the current user and current dir
USER ${USER}
VOLUME ${PWD}
WORKDIR ${PWD}
EOF

docker build -t "${DOCKER_NAME}" -f "${DOCKERFILE}" "${DOCKER_DIR}"

# extra rights needed for KVM
sudo docker run \
    --init \
    -v "${PWD}:${PWD}" \
    -v "${HOME}/.ccache:${HOME}/.ccache" \
    --privileged \
    --rm ${DOCKER_EXTRA_ARGS:+"${DOCKER_EXTRA_ARGS}"} \
    "${DOCKER_NAME}" \
    bash "-${-}" "${SCRIPT}" "${SCRIPT_OPTS[@]}"
