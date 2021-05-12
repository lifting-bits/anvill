ARG LLVM_VERSION=11
ARG ARCH=amd64
ARG UBUNTU_VERSION=18.04
ARG DISTRO_BASE=ubuntu${UBUNTU_VERSION}
ARG BUILD_BASE=ubuntu:${UBUNTU_VERSION}
ARG LIBRARIES=/opt/trailofbits

# Run-time dependencies go here
FROM ${BUILD_BASE} AS base
ARG UBUNTU_VERSION
ARG LIBRARIES
RUN apt-get update && \
    apt-get install -qqy --no-install-recommends python3 python3-pip python3.8 python3.8-venv python3-setuptools xz-utils && \
    rm -rf /var/lib/apt/lists/*

# Build-time dependencies go here
FROM trailofbits/cxx-common-vcpkg-builder-ubuntu:${UBUNTU_VERSION} as deps
ARG UBUNTU_VERSION
ARG ARCH
ARG LLVM_VERSION
ARG LIBRARIES
RUN apt-get update && \
    apt-get install -qqy python3 python3.8 python3.8-venv python3-pip libc6-dev wget liblzma-dev zlib1g-dev curl git build-essential ninja-build libselinux1-dev libbsd-dev ccache pixz xz-utils make rpm && \
    if [ "$(uname -m)" = "x86_64" ]; then dpkg --add-architecture i386 && apt-get update && apt-get install -qqy gcc-multilib g++-multilib zip zlib1g-dev:i386; fi && \
    rm -rf /var/lib/apt/lists/*

# Build dependencies
WORKDIR /dependencies
RUN git clone --depth=1 --branch master https://github.com/lifting-bits/remill.git && \
    cd remill && \
    ./scripts/build.sh --llvm-version ${LLVM_VERSION} --prefix ${LIBRARIES} --download-dir /tmp

# Make this a separate RUN because the build script above downloads a lot
RUN cd remill && \
    cmake --build remill-build --target install -- -j "$(nproc)"


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

RUN source ${VIRTUAL_ENV}/bin/activate && \
    cmake -G Ninja -B build -S . \
        -DANVILL_ENABLE_INSTALL_TARGET=true \
        -Dremill_DIR:PATH=${LIBRARIES}/lib/cmake/remill \
        -DANVILL_INSTALL_PYTHON3_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX:PATH="${LIBRARIES}" \
        -DCMAKE_VERBOSE_MAKEFILE=True \
        -DVCPKG_ROOT=/tmp/vcpkg_ubuntu-${UBUNTU_VERSION}_llvm-${LLVM_VERSION}_amd64 \
        && \
    cmake --build build --target install

FROM base AS dist
ARG LLVM_VERSION
ENV PATH="/opt/trailofbits/bin:${PATH}" \
    LLVM_VERSION=llvm${LLVM_VERSION} \
    VIRTUAL_ENV=/opt/trailofbits/venv

RUN apt-get update && \
    apt-get install -qqy unzip python3.8 python3.8-venv python3-pip && \
    rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-c"]

# The below is commented out since neither binja
# nor IDA would be available in the dist container
# so it makes no sense to also add Python -- can't test the Python API
# without either of those.
# If the situation changes, this can be uncommented to also install Python in the dist image
#RUN apt-get update && \
#    apt-get install -qqy python3.8 python3-pip python3.8-venv && \
#    rm -rf /var/lib/apt/lists/*
# Allow for mounting of local folder
WORKDIR /anvill/local

COPY scripts/docker-decompile-json-entrypoint.sh /opt/trailofbits/docker-decompile-json-entrypoint.sh
COPY --from=build ${LIBRARIES} ${LIBRARIES}
ENTRYPOINT ["/opt/trailofbits/docker-decompile-json-entrypoint.sh"]
