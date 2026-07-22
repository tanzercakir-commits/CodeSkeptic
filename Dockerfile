# CodeSkeptic — one-command trial and CI image.
#
#   docker run --rm -v "$PWD:/work" ghcr.io/tanzercakir-commits/codeskeptic \
#       src/ --build-path build --sarif out.sarif
#
# The runtime stage carries libc/libstdc++ DEV HEADERS on purpose:
# analyzing code needs the target's own headers, exactly like a
# compiler. Mount your project at /work (the default workdir).
FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        llvm-20-dev libclang-20-dev clang-20 libzstd-dev zlib1g-dev \
        cmake ninja-build g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY . /src
RUN cmake -S /src -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH=/usr/lib/llvm-20 \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
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
WORKDIR /work
ENTRYPOINT ["codeskeptic"]
