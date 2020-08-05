ARG LLVM_VERSION=900
ARG ARCH=amd64
ARG LIBRARIES=/opt/trailofbits/libraries
ARG DISTRO_BASE=ubuntu18.04

# Build-time dependencies go here
FROM trailofbits/cxx-common:llvm${LLVM_VERSION}-${DISTRO_BASE}-${ARCH} as deps
#FROM trailofbits/remill:llvm${LLVM_VERSION}-${DISTRO_BASE}-${ARCH} as deps
ARG LIBRARIES

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -qqy ninja-build python2.7 python3 python3-pip liblzma-dev zlib1g-dev libtinfo-dev curl git wget build-essential ninja-build ccache && \
    rm -rf /var/lib/apt/lists/*

# needed for 20.04 support until we migrate to py3
RUN curl https://bootstrap.pypa.io/get-pip.py --output get-pip.py && python2.7 get-pip.py

RUN update-alternatives --install /usr/bin/python2 python2 /usr/bin/python2.7 1

# Build in the remill build directory

WORKDIR /
COPY .remill_commit_id ./
RUN git clone https://github.com/lifting-bits/remill.git && \
    cd remill && \
    echo "Using remill commit $(cat ../.remill_commit_id)" && \
    git checkout $(cat ../.remill_commit_id)

RUN mkdir -p /remill/tools/anvill
WORKDIR /remill/tools/anvill

COPY . ./

#TODO(artem): find a way to use remill commit id; for now just use latest build of remill
# RUN cd /remill && git checkout -b temp $(</remill/tools/anvill/.remil_commit_id) && cd /remill/tools/anvill

ENV PATH="${LIBRARIES}/llvm/bin:${LIBRARIES}/cmake/bin:${LIBRARIES}/protobuf/bin:${PATH}"
ENV CC="${LIBRARIES}/llvm/bin/clang"
ENV CXX="${LIBRARIES}/llvm/bin/clang++"
ENV TRAILOFBITS_LIBRARIES="${LIBRARIES}"

WORKDIR /remill
RUN mkdir -p build && cd build && \
    cmake -G Ninja -DCMAKE_VERBOSE_MAKEFILE=True -DCMAKE_INSTALL_PREFIX=/opt/trailofbits/remill .. && \
    cmake --build . --target install && \
    cd .. && rm -rf build

