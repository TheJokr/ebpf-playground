# Adapted from https://github.com/devcontainers/images/tree/v0.3.26/src/go
FROM golang:1.21-bookworm

# C -> eBPF toolchain
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends clang llvm \
    linux-libc-dev libbpf-dev bpftool libcap2-bin \
    && apt-get -y clean
