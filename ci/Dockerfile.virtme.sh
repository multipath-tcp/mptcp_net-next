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
VIRTME_GIT_SHA="88cd30f073714bd097d83bc7a6b028c0e4bf7a2b"

PACKETDRILL_GIT_URL="https://github.com/multipath-tcp/packetdrill.git"
PACKETDRILL_GIT_BRANCH="mptcp-net-next"

LIBPCAP_GIT_URL="https://github.com/the-tcpdump-group/libpcap.git"
LIBPCAP_GIT_SHA="9d5a1f262a57cc93df74906ea912accc5bedf7f0" # sync with tcpdump
TCPDUMP_GIT_URL="https://github.com/the-tcpdump-group/tcpdump.git"
TCPDUMP_GIT_SHA="c429fc4120116c407acf4f4df483ac5f069e2a63" # last tag has no MPTCPv1 support

IPROUTE2_GIT_URL="git://git.kernel.org/pub/scm/network/iproute2/iproute2-next.git"
IPROUTE2_GIT_SHA="9c3be2c0eee01be7832b7900a8be798a19c659a5" # pre v5.8.0 with MPTCP support in ss
# last tag
#IPROUTE2_GIT_SHA="$(curl https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/ 2>/dev/null | \
#                         grep -o 'iproute2-[0-9]\+\.[0-9]\+\.[0-9]\+\.tar\.xz' | \
#                         tail -n1 | \
#                         grep -o "[0-9]\+\.[0-9]\+\.[0-9]")
#IPROUTE2_GIT_URL="git://git.kernel.org/pub/scm/network/iproute2/iproute2.git"

DOCKERFILE=$(mktemp --tmpdir="${DOCKER_DIR}")
trap 'rm -f "${DOCKERFILE}"' EXIT

cat <<EOF > "${DOCKERFILE}"
FROM ubuntu:20.04

# Use the same rights as the launcher
RUN mkdir -p "$(dirname "${HOME}")" && \
    useradd -ms /bin/bash -u "${UID}" -U "${USER}" -d "${HOME}"

# dependencies for the script
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends \
                    build-essential libncurses5-dev gcc libssl-dev bc bison \
                    libelf-dev flex git curl tar hashalot qemu-kvm sudo expect \
                    python3 python3-pkg-resources busybox \
                    iputils-ping ethtool klibc-utils kbd rsync ccache \
                    ca-certificates gnupg2 net-tools kmod \
                    libdbus-1-dev libnl-genl-3-dev libibverbs-dev \
                    libsmi2-dev libcap-ng-dev \
                    pkg-config libmnl-dev \
                    clang lld llvm libcap-dev && \
    apt-get clean

# virtme
RUN cd /opt && \
    git clone "${VIRTME_GIT_URL}" && \
    cd virtme && \
        git checkout "${VIRTME_GIT_SHA}"

# libpcap & tcpdump
RUN cd /opt && \
    git clone "${LIBPCAP_GIT_URL}" libpcap && \
    git clone "${TCPDUMP_GIT_URL}" tcpdump && \
    cd libpcap && \
        git checkout "${LIBPCAP_GIT_SHA}" && \
        ./configure --prefix=/usr && \
        make -j"$(nproc)" -l"$(nproc)" && \
        make install && \
    cd ../tcpdump && \
        git checkout "${TCPDUMP_GIT_SHA}" && \
        ./configure --prefix=/usr && \
        make -j"$(nproc)" -l"$(nproc)" && \
        make install

# iproute
RUN cd /opt && \
    git clone "${IPROUTE2_GIT_URL}" iproute2 && \
    cd iproute2 && \
        git checkout "${IPROUTE2_GIT_SHA}" && \
        ./configure && \
        make -j"$(nproc)" -l"$(nproc)" && \
        make install

# packetdrill
ENV PACKETDRILL_GIT_BRANCH "${PACKETDRILL_GIT_BRANCH}"
RUN cd /opt && \
    git clone "${PACKETDRILL_GIT_URL}" && \
    cd packetdrill && \
        git checkout "${PACKETDRILL_GIT_BRANCH}" && \
        cd gtests/net/packetdrill/ && \
            ./configure && \
            make -j"$(nproc)" -l"$(nproc)" && \
            ln -s /opt/packetdrill/gtests/net/packetdrill/packetdrill /usr/sbin/

# sudo rights (for kvm)
RUN usermod -a -G sudo "${USER}" && \
    echo "${USER} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# to quickly shutdown the VM
RUN ln -sv /usr/lib/klibc/bin/poweroff /usr/sbin/

# CCache for quicker builds with default colours
# Note: use 'ccache -M xG' to increase max size, default is 5GB
ENV PATH /usr/lib/ccache:\${PATH}
ENV CCACHE_COMPRESS true
ENV KBUILD_BUILD_TIMESTAMP ""
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
