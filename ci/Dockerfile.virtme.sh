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
if [ "${1}" = "manual" ] || [ "${1}" = "debug" ]; then
        DOCKER_EXTRA_ARGS="-it"
fi

VIRTME_GIT_URL="git://git.kernel.org/pub/scm/utils/kernel/virtme/virtme.git"
VIRTME_GIT_SHA="88cd30f073714bd097d83bc7a6b028c0e4bf7a2b"

PACKETDRILL_GIT_URL="https://github.com/multipath-tcp/packetdrill.git"
PACKETDRILL_GIT_BRANCH="mptcp-net-next"

LIBPCAP_GIT_URL="https://github.com/the-tcpdump-group/libpcap.git"
LIBPCAP_GIT_SHA="2d3a47d5386d11c6e6c141afd50bdb56e2b087ce" # sync with tcpdump
TCPDUMP_GIT_URL="https://github.com/the-tcpdump-group/tcpdump.git"
TCPDUMP_GIT_SHA="19b771391ac80dea38c26eb3a71fef148034ebf4" # last tag has no MPTCPv1 support

#IPROUTE2_GIT_URL="git://git.kernel.org/pub/scm/network/iproute2/iproute2-next.git"
#IPROUTE2_GIT_SHA="9c3be2c0eee01be7832b7900a8be798a19c659a5" # pre v5.8.0 with MPTCP support in ss
# last tag
IPROUTE2_GIT_SHA="v$(curl https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/ 2>/dev/null | \
                         grep -o 'iproute2-[0-9]\+\.[0-9]\+\.[0-9]\+\.tar\.xz' | \
                         tail -n1 | \
                         grep -o "[0-9]\+\.[0-9]\+\.[0-9]")"
IPROUTE2_GIT_URL="git://git.kernel.org/pub/scm/network/iproute2/iproute2.git"

BYOBU_URL="https://launchpad.net/byobu/trunk/5.133/+download/byobu_5.133.orig.tar.gz"
BYOBU_MD5="0ff03f3795cc08aae50c1ab117c03261 byobu.tar.gz"

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
                    clang lld llvm libcap-dev \
                    gdb crash dwarves \
                    iptables ebtables nftables vim psmisc bash-completion \
                    gettext-base libevent-dev libnewt0.52 libslang2 libutempter0 python3-newt tmux && \
    apt-get clean

# virtme
RUN cd /opt && \
    git clone "${VIRTME_GIT_URL}" && \
    cd virtme && \
        git checkout "${VIRTME_GIT_SHA}"

# byobu (not to have a dep to iproute2)
RUN cd /opt && \
    curl -L "${BYOBU_URL}" -o byobu.tar.gz && \
    echo "${BYOBU_MD5}" | md5sum -c && \
    tar xzf byobu.tar.gz && \
    cd byobu-*/ && \
        ./configure --prefix=/usr && \
        make && \
        sudo make install

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
RUN for i in /usr/lib/klibc/bin/*; do type "\$(basename "\${i}")" >/dev/null 2>&1 || ln -sv "\${i}" /usr/sbin/; done

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
