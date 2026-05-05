# scribe in a container. Build:
#   docker build -t scribe .
# Run against a binary on the host:
#   docker run --rm -v "$PWD":/work scribe info /work/myapp
# Or against an image already in the local docker daemon (mount the
# socket — only do this in trusted environments):
#   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock scribe sbom 'docker://alpine:3.19'

FROM alpine:3.19 AS build
RUN apk add --no-cache curl xz
ARG ZIG_VERSION=0.16.0
RUN ARCH="$(uname -m)" && \
    case "$ARCH" in \
      x86_64)   ZSUFFIX=linux-x86_64 ;; \
      aarch64)  ZSUFFIX=linux-aarch64 ;; \
      *) echo "unsupported arch $ARCH" && exit 1 ;; \
    esac && \
    curl -sSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZSUFFIX}-${ZIG_VERSION}.tar.xz" \
      | tar -xJ -C /opt && \
    mv "/opt/zig-${ZSUFFIX}-${ZIG_VERSION}" /opt/zig
ENV PATH=/opt/zig:$PATH

WORKDIR /src
COPY . .
RUN zig build -Doptimize=ReleaseFast

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=build /src/zig-out/bin/scribe /usr/local/bin/scribe
ENTRYPOINT ["/usr/local/bin/scribe"]
CMD ["--help"]
