#! /bin/bash
#
# Generate a Dockerfile, build it and run update-tg-tree.sh script

# We should manage all errors in this script
set -e

SCRIPT="${1:-./update-tg-tree.sh}"
if ! test -f "${SCRIPT}"; then
    echo "Unable to execute ${SCRIPT} from ${PWD}"
    exit 1
fi
shift
SCRIPT_OPTS=("${@}")

DOCKER_NAME="update-tg-tree"
DOCKER_DIR=$(dirname "${0}")

TG_SETUP_URL="https://github.com/mackyle/topgit/releases/download/topgit-0.19.12/topgit-0.19.12.tar.gz"
TG_SETUP_TARBALL="topgit.tar.gz"
TG_SETUP_SHA="8b6b89c55108cc75d007f63818e43aa91b69424b5b8384c06ba2aa3122f5e440  ${TG_SETUP_TARBALL}"

SPARSE_URL_BASE="https://mirrors.edge.kernel.org/pub/software/devel/sparse/dist/"
# Force rebuild if a new version is available
SPARSE_TARBALL=$(curl "${SPARSE_URL_BASE}" 2>/dev/null | \
                      grep -o 'sparse-[0-9]\+\.[0-9]\+\.[0-9]\+\.tar\.xz' | \
                      tail -n1)
SPARSE_URL="${SPARSE_URL_BASE}${SPARSE_TARBALL}"
SPARSE_SHA256SUM="${SPARSE_URL_BASE}sha256sums.asc" ## TODO check sig


DOCKERFILE=$(mktemp --tmpdir="${DOCKER_DIR}")
trap 'rm -f "${DOCKERFILE}"' EXIT

cat <<EOF > "${DOCKERFILE}"
FROM ubuntu:latest

# Use the same rights as the launcher
RUN mkdir -p "$(dirname "${HOME}")" && \
    useradd -ms /bin/bash -u "${UID}" -U "${USER}" -d "${HOME}"

# dependencies for the script
RUN apt-get update && \
    apt-get install -y build-essential libncurses5-dev gcc libssl-dev bc bison \
                       libelf-dev flex git curl tar hashalot ccache && \
    apt-get clean

# TopGit
RUN curl -L "${TG_SETUP_URL}" -o "${TG_SETUP_TARBALL}" && \
    echo "${TG_SETUP_SHA}" > sha && \
    sha256sum --check sha && \
    rm sha && \
    tar xzf "${TG_SETUP_TARBALL}" && \
    cd "topgit-"* && \
        make prefix="/usr" install && \
        cd .. && \
    rm -rf "${TG_SETUP_TARBALL}" "topgit-"*

RUN curl -L "${SPARSE_URL}" -o "${SPARSE_TARBALL}" && \
    curl -L "${SPARSE_SHA256SUM}" | grep "${SPARSE_TARBALL}" > sha && \
    sha256sum --check sha && \
    rm sha && \
    tar xJf "${SPARSE_TARBALL}" && \
    cd "${SPARSE_TARBALL:0:-7}" && \
        make && \
        make PREFIX=/usr install && \
        cd .. && \
    rm -rf "${SPARSE_TARBALL:0:-7}" "${SPARSE_TARBALL}"

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
# ssh and gitconfig is needed to create commits and pull/push
docker run \
    --init \
    -e "UPD_TG_FORCE_SYNC=${UPD_TG_FORCE_SYNC}" \
    -e "UPD_TG_NOT_BASE=${UPD_TG_NOT_BASE}" \
    -e "UPD_TG_VALIDATE_EACH_TOPIC=${UPD_TG_VALIDATE_EACH_TOPIC}" \
    -v "${PWD}:${PWD}" \
    -v "${HOME}/.ssh:${HOME}/.ssh" \
    -v "${HOME}/.gitconfig:${HOME}/.gitconfig:ro" \
    -v "${HOME}/.ccache:${HOME}/.ccache" \
    --rm "${DOCKER_NAME}" \
    bash "-${-}" "${SCRIPT}" "${SCRIPT_OPTS[@]}"
