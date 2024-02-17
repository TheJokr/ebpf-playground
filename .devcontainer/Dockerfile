# Adapted from https://github.com/devcontainers/images/tree/v0.3.26/src/go
FROM golang:1.21-bookworm

# C -> eBPF toolchain
RUN dpkg --add-architecture amd64 && dpkg --add-architecture arm64 \
    # TODO(1.87): requirements check breaks with multiple libc variants
    && touch /tmp/vscode-skip-server-requirements-check \
    && apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends clang llvm \
    libbpf-dev bpftool libcap2-bin libc6-dev:amd64 libc6-dev:arm64 \
    linux-libc-dev:amd64 linux-libc-dev:arm64 \
    && apt-get -y clean
