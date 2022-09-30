ARG LLVM_VERSION=14
ARG ARCH=amd64
ARG UBUNTU_VERSION=20.04
ARG CXX_COMMON_VERSION=0.2.10
ARG DISTRO_BASE=ubuntu${UBUNTU_VERSION}
ARG BUILD_BASE=ubuntu:${UBUNTU_VERSION}
ARG LIBRARIES=/opt/trailofbits
ARG BINJA_DECODE_KEY


# Run-time dependencies go here
FROM ${BUILD_BASE} AS base
ARG UBUNTU_VERSION
ARG LIBRARIES
ARG LLVM_VERSION
ARG CXX_COMMON_VERSION
ARG DEBIAN_FRONTEND=noninteractive 
RUN apt-get update && \
    apt-get install -qqy --no-install-recommends git libdbus-1-3 curl unzip python3 python3-pip python3.8 python3.8-venv python3-setuptools xz-utils cmake && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /dependencies

RUN tar -xJf vcpkg_ubuntu-${UBUNTU_VERSION}_llvm-${LLVM_VERSION}_amd64.tar.xz && \
    rm vcpkg_ubuntu-${UBUNTU_VERSION}_llvm-${LLVM_VERSION}_amd64.tar.xz


#### NOTE ####
# Remill needs to be installed in the base _and_ deps stages, because they have
# different base images


# Build-time dependencies go here
FROM trailofbits/cxx-common-vcpkg-builder-ubuntu:${UBUNTU_VERSION} as deps
ARG UBUNTU_VERSION
ARG ARCH
ARG LLVM_VERSION
ARG CXX_COMMON_VERSION
ARG LIBRARIES
ARG REMILL_COMMIT_ID=master

RUN apt-get update && \
    apt-get install -qqy xz-utils python3.8-venv make rpm && \
    rm -rf /var/lib/apt/lists/*

# Build dependencies
WORKDIR /dependencies



# cxx-common
ADD https://github.com/lifting-bits/cxx-common/releases/download/v${CXX_COMMON_VERSION}/vcpkg_ubuntu-${UBUNTU_VERSION}_llvm-${LLVM_VERSION}_amd64.tar.xz vcpkg_ubuntu-${UBUNTU_VERSION}_llvm-${LLVM_VERSION}_amd64.tar.xz
RUN tar -xJf vcpkg_ubuntu-${UBUNTU_VERSION}_llvm-${LLVM_VERSION}_amd64.tar.xz && \
    rm vcpkg_ubuntu-${UBUNTU_VERSION}_llvm-${LLVM_VERSION}_amd64.tar.xz


RUN git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com" && git config --global user.name "github-actions[bot]"
RUN git clone "https://github.com/lifting-bits/remill.git" remill && cd remill && git checkout ${REMILL_COMMIT_ID}

RUN mkdir /dependencies/remill_build

WORKDIR /dependencies/remill_build


RUN cmake -G Ninja -B build -S  /dependencies/remill \
    -DREMILL_ENABLE_INSTALL=true \
    -DCMAKE_INSTALL_PREFIX=${LIBRARIES} \
    -DCMAKE_VERBOSE_MAKEFILE=True \
    -DVCPKG_ROOT=/dependencies/vcpkg_ubuntu-${UBUNTU_VERSION}_llvm-${LLVM_VERSION}_amd64 \
    && \
    cmake --build build --target install 

# Source code build
FROM deps AS build
WORKDIR /anvill
ARG UBUNTU_VERSION
ARG ARCH
ARG LLVM_VERSION
ARG LIBRARIES

ENV VIRTUAL_ENV=/opt/trailofbits/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

# create a virtualenv in /opt/trailofbits/venv
RUN python3.8 -m venv ${VIRTUAL_ENV}

# Needed for sourcing venv
SHELL ["/bin/bash", "-c"]

COPY . ./

# Source venv, build Anvill, Install binaries & system packages
RUN source ${VIRTUAL_ENV}/bin/activate && \
    cmake -G Ninja -B build -S . \
    -DANVILL_ENABLE_INSTALL=true \
    -Dremill_DIR=${LIBRARIES}/cmake/remill \
    -Dsleigh_DIR=${LIBRARIES}/cmake/sleigh \
    -DCMAKE_INSTALL_PREFIX:PATH="${LIBRARIES}" \
    -DCMAKE_VERBOSE_MAKEFILE=True \
    -DVCPKG_ROOT=/dependencies/vcpkg_ubuntu-${UBUNTU_VERSION}_llvm-${LLVM_VERSION}_amd64 \
    && \
    cmake --build build --target install

FROM base AS dist
ARG LLVM_VERSION
ARG LIBRARIES
ENV PATH="/opt/trailofbits/bin:${PATH}" \
    LLVM_VERSION_NUM=${LLVM_VERSION} \
    LLVM_VERSION=llvm${LLVM_VERSION}

# Allow for mounting of local folder
WORKDIR /anvill/local

COPY --from=build ${LIBRARIES} ${LIBRARIES}

# Target no longer installs at a version

ENTRYPOINT ["anvill-decompile-json"]


FROM dist as binja
ARG BINJA_DECODE_KEY
ARG BINJA_VERSION
ARG BINJA_CHANNEL

ENV VIRTUAL_ENV=/opt/trailofbits/venv

SHELL ["/bin/bash", "-c"]
RUN apt-get update && \
    apt-get install -qqy gpg unzip && \
    rm -rf /var/lib/apt/lists/*

COPY ci /dependencies/binja_install

RUN export BINJA_DECODE_KEY="${BINJA_DECODE_KEY}" && \
    source ${VIRTUAL_ENV}/bin/activate && \
    cd /dependencies/binja_install && \
    if [[ "${BINJA_DECODE_KEY}" != "" ]]; then ./install_binja.sh && python3 switcher.py --version_string ${BINJA_VERSION} ${BINJA_CHANNEL}; fi

# Keep this here to sanity check Binary Ninja API Installation & version
RUN python3 --version && python3 -c "import binaryninja; print(binaryninja.core_version())"

COPY scripts/docker-spec-entrypoint.sh /opt/trailofbits/docker-spec-entrypoint.sh
ENTRYPOINT ["/opt/trailofbits/docker-spec-entrypoint.sh"]


# This appears last so that it's default
FROM dist
