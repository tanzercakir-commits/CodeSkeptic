# Two explicit profiles; see docs/integrations.md before running a container.
# artifact-runtime consumes only a checksum-verified prepared package context,
# with a caller-pinned cached base image and no build/run network. It deliberately
# does not invent target development headers. scripts/action_container.py stages
# that context and supplies read-only source mounts and bounded runtime isolation.
ARG CODESKEPTIC_RUNTIME_BASE=ubuntu:24.04
FROM ${CODESKEPTIC_RUNTIME_BASE} AS artifact-runtime
COPY package/ /opt/codeskeptic/
ENV PATH="/opt/codeskeptic/bin:${PATH}"
USER 65532:65532
# This directory physically exists from COPY, even under a read-only runtime.
WORKDIR /opt/codeskeptic
ENTRYPOINT ["codeskeptic"]

# Preserve the default source-backed release build, including historical source
# contexts used by docker.yml (which do not have the new helper scripts).
# This distinct networked rebuild is NOT qualified by an offline artifact test.
FROM ubuntu:24.04 AS build
ARG CODESKEPTIC_VERSION_OVERRIDE=""
RUN apt-get update && apt-get install -y --no-install-recommends \
        llvm-20-dev libclang-20-dev clang-20 libzstd-dev zlib1g-dev \
        cmake ninja-build g++ ca-certificates python3 binutils \
    && rm -rf /var/lib/apt/lists/*
COPY . /src
RUN cmake -S /src -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH=/usr/lib/llvm-20 \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
        -DCODESKEPTIC_BUILD_TESTS=OFF \
        -DCODESKEPTIC_VERSION_OVERRIDE="$CODESKEPTIC_VERSION_OVERRIDE" \
    && cmake --build /build \
    && bash /src/scripts/package_release.sh /build/src/codeskeptic /dist clang-20

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        libzstd1 zlib1g libc6-dev g++ \
    && rm -rf /var/lib/apt/lists/*
# The relocatable tree: bin/codeskeptic finds lib/clang/<N>/include
# exe-relative (ResourceDir.cpp) — no LLVM install in this stage.
COPY --from=build /dist/codeskeptic-*/ /opt/codeskeptic/
ENV PATH="/opt/codeskeptic/bin:${PATH}"
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["codeskeptic"]
