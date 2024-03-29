#!/usr/bin/env bash
set -euo pipefail

# Simple service mesh example for demonstration
# Based on https://github.com/nicholasjackson/fake-service
if [[ ! -x /tmp/fake-service ]]; then
    case "$(uname -m)" in
    aarch64) arch='arm64';;
    x86_64) arch='amd64';;
    *) echo 'Unsupported architecture' >&2; exit 1;;
    esac

    tmpdst="$(mktemp)"
    curl -fL --proto '=https' -o "$tmpdst" "https://github.com/nicholasjackson/fake-service/releases/download/v0.26.2/fake_service_linux_${arch}.zip"
    unzip "$tmpdst" fake-service -d /tmp
    chmod a+x /tmp/fake-service
    rm -f "$tmpdst"
fi


export LOG_LEVEL=warn UPSTREAM_WORKERS=2
export TIMING_50_PERCENTILE='0.1s' TIMING_99_PERCENTILE='0.5s'

NAME=authz LISTEN_ADDR='localhost:8081' /tmp/fake-service &
NAME=users LISTEN_ADDR='localhost:8082' /tmp/fake-service &

UPSTREAM_URIS='http://localhost:8081,https://example.com,https://example.net' \
NAME=inventory LISTEN_ADDR='localhost:8083' /tmp/fake-service &

UPSTREAM_URIS='http://localhost:8082,https://github.com/nicholasjackson/fake-service' \
NAME=proxy-ext LISTEN_ADDR='localhost:8084' /tmp/fake-service &

UPSTREAM_URIS='http://localhost:8081,http://localhost:8083,http://localhost:8084' \
NAME=api LISTEN_ADDR='localhost:8080' /tmp/fake-service &

echo 'fake-mesh entrypoint listening at http://localhost:8080/'
wait
