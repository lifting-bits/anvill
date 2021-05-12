ARG LLVM_VERSION=11
ARG ARCH=amd64
ARG UBUNTU_VERSION=18.04
ARG DISTRO_BASE=ubuntu${UBUNTU_VERSION}
ARG BUILD_BASE=ubuntu:${UBUNTU_VERSION}
ARG LIBRARIES=/opt/trailofbits
ARG BINJA_DECODE_KEY

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
    apt-get install -qqy xz-utils python3.8-venv make rpm && \
    rm -rf /var/lib/apt/lists/*

# Build dependencies
WORKDIR /dependencies
RUN git clone --depth=1 --branch master https://github.com/lifting-bits/remill.git && \
    cd remill && \
    ./scripts/build.sh --llvm-version ${LLVM_VERSION} --prefix ${LIBRARIES} --download-dir /dependencies

# Make this a separate RUN because the build script above downloads a lot
RUN cd remill && \
    dpkg -i remill-build/*.deb

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
        -DVCPKG_ROOT=/dependencies/vcpkg_ubuntu-${UBUNTU_VERSION}_llvm-${LLVM_VERSION}_amd64 \
        && \
    cmake --build build --target install

# set up a symlink to invoke without a version
RUN update-alternatives --install \
    /opt/trailofbits/bin/anvill-decompile-json \
    anvill-decompile-json \
    /opt/trailofbits/bin/anvill-decompile-json-${LLVM_VERSION}.0 \
    100

FROM base AS dist
ARG LLVM_VERSION
ARG LIBRARIES
ENV PATH="/opt/trailofbits/bin:${PATH}" \
    LLVM_VERSION=llvm${LLVM_VERSION}

# Allow for mounting of local folder
WORKDIR /anvill/local

COPY scripts/docker-decompile-json-entrypoint.sh /opt/trailofbits/docker-decompile-json-entrypoint.sh
COPY --from=build ${LIBRARIES} ${LIBRARIES}
ENTRYPOINT ["/opt/trailofbits/docker-decompile-json-entrypoint.sh"]


FROM dist as binja
ARG BINJA_DECODE_KEY

ENV VIRTUAL_ENV=/opt/trailofbits/venv

SHELL ["/bin/bash", "-c"]
RUN apt-get update && \
    apt-get install -qqy gpg unzip && \
    rm -rf /var/lib/apt/lists/*

COPY ci /dependencies/binja_install

RUN export BINJA_DECODE_KEY="${BINJA_DECODE_KEY}" && \
    source ${VIRTUAL_ENV}/bin/activate && \
    cd /dependencies/binja_install && \
    if [[ "${BINJA_DECODE_KEY}" != "" ]]; then ./install_binja.sh; fi
COPY scripts/docker-spec-entrypoint.sh /opt/trailofbits/docker-spec-entrypoint.sh
ENTRYPOINT ["/opt/trailofbits/docker-spec-entrypoint.sh"]


# This appears last so that it's default
FROM dist
