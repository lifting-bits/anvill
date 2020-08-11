ARG LLVM_VERSION=800
ARG ARCH=amd64
ARG UBUNTU_VERSION=18.04
ARG DISTRO_BASE=ubuntu${UBUNTU_VERSION}
ARG BUILD_BASE=ubuntu:${UBUNTU_VERSION}
ARG LIBRARIES=/opt/trailofbits/libraries

# Will copy remill installation from here
FROM trailofbits/remill:llvm${LLVM_VERSION}-${DISTRO_BASE}-${ARCH} as remill

# Additional runtime dependencies go here
FROM ${BUILD_BASE} as base
ARG UBUNTU_VERSION
RUN apt-get update && \
    if [ "${UBUNTU_VERSION}" = "20.04" ] ; then \
        apt-get install -qqy --no-install-recommends libtinfo6 ; \
    else \
        apt-get install -qqy --no-install-recommends libtinfo5 ; \
    fi && \
    rm -rf /var/lib/apt/lists/*

# Build-time dependencies go here
FROM trailofbits/cxx-common:llvm${LLVM_VERSION}-${DISTRO_BASE}-${ARCH} as deps
ARG LIBRARIES

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    if [ "$(uname -m)" = "x86_64" ]; then apt-get install -qqy gcc-multilib g++-multilib; fi && \
    apt-get install -qqy ninja-build python2.7 python3 python3-pip liblzma-dev zlib1g-dev libtinfo-dev curl git wget build-essential ninja-build ccache && \
    rm -rf /var/lib/apt/lists/*

# needed for 20.04 support until we migrate to py3
RUN curl https://bootstrap.pypa.io/get-pip.py --output get-pip.py && python2.7 get-pip.py

RUN update-alternatives --install /usr/bin/python2 python2 /usr/bin/python2.7 1


COPY --from=remill /opt/trailofbits/remill /opt/trailofbits/remill


# Source code build
FROM deps as build
ARG LIBRARIES

WORKDIR /anvill
COPY . ./

ENV PATH="${LIBRARIES}/llvm/bin:${LIBRARIES}/cmake/bin:${LIBRARIES}/protobuf/bin:${PATH}"
ENV CC="${LIBRARIES}/llvm/bin/clang"
ENV CXX="${LIBRARIES}/llvm/bin/clang++"
ENV TRAILOFBITS_LIBRARIES="${LIBRARIES}"

RUN mkdir -p build && cd build && \
    cmake -G Ninja -DCMAKE_PREFIX_PATH=/opt/trailofbits/remill -DCMAKE_VERBOSE_MAKEFILE=True -DCMAKE_INSTALL_PREFIX=/opt/trailofbits/anvill .. && \
    cmake --build . --target install

FROM base as dist
ARG LLVM_VERSION

# Allow for mounting of local folder
WORKDIR /anvill/local

COPY scripts/docker-decompile-json-entrypoint.sh /opt/trailofbits/anvill/docker-decompile-json-entrypoint.sh
COPY --from=remill /opt/trailofbits/remill /opt/trailofbits/remill
COPY --from=build /opt/trailofbits/anvill /opt/trailofbits/anvill
ENV LLVM_VERSION=llvm${LLVM_VERSION} \
    PATH="/opt/trailofbits/anvill/bin:${PATH}"
ENTRYPOINT ["/opt/trailofbits/anvill/docker-decompile-json-entrypoint.sh"]
