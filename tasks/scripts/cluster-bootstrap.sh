#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# shellcheck source=_container-runtime.sh
source "$(dirname "$0")/_container-runtime.sh"

# Normalize cluster name: lowercase, replace invalid chars with hyphens
normalize_name() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//'
}

port_is_in_use() {
  local port=$1
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi

  if command -v nc >/dev/null 2>&1; then
    nc -z 127.0.0.1 "${port}" >/dev/null 2>&1
    return $?
  fi

  (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1
}

pick_random_port() {
  local lower=20000
  local upper=60999
  local attempts=256
  local port

  for _ in $(seq 1 "${attempts}"); do
    port=$((RANDOM % (upper - lower + 1) + lower))
    if ! port_is_in_use "${port}"; then
      echo "${port}"
      return 0
    fi
  done

  echo "Error: could not find a free port after ${attempts} attempts." >&2
  return 1
}

# Resolve the port for the local registry container.
# - If the registry container already exists, reuse the port it is mapped to.
# - If port 5000 is free, use it.
# - Otherwise, scan 5001-5099 for a free port (e.g. macOS AirPlay Receiver owns 5000).
resolve_registry_port() {
  local _container="${LOCAL_REGISTRY_CONTAINER:-openshell-local-registry}"

  if "${CONTAINER_CMD}" inspect "${_container}" >/dev/null 2>&1; then
    local _mapped
    # Use HostConfig (works on stopped containers; `port` requires a running container).
    _mapped=$("${CONTAINER_CMD}" inspect "${_container}" \
      --format '{{range $p, $b := .HostConfig.PortBindings}}{{if eq $p "5000/tcp"}}{{range $b}}{{.HostPort}}{{end}}{{end}}{{end}}' \
      2>/dev/null || true)
    if [ -n "${_mapped}" ] && [ "${_mapped}" != "0" ]; then
      # Only reuse this port if it is actually free (or held by the registry itself).
      if ! port_is_in_use "${_mapped}"; then
        echo "${_mapped}"
        return
      fi
      # Port is taken by something else — fall through to pick a new one.
    fi
  fi

  if ! port_is_in_use 5000; then
    echo 5000
    return
  fi

  local _alt
  for _alt in $(seq 5001 5099); do
    if ! port_is_in_use "${_alt}"; then
      echo "Port 5000 is already in use by another process (e.g. macOS AirPlay Receiver)." >&2
      echo "Using port ${_alt} for the local registry instead." >&2
      echo "To free port 5000: System Settings → General → AirDrop & Handoff → disable AirPlay Receiver." >&2
      echo "${_alt}"
      return
    fi
  done

  pick_random_port
}

MODE=${1:-build}
if [ "${MODE}" != "build" ] && [ "${MODE}" != "fast" ]; then
  echo "usage: $0 [build|fast]" >&2
  exit 1
fi

if [ -n "${IMAGE_TAG:-}" ]; then
  IMAGE_TAG=${IMAGE_TAG}
else
  IMAGE_TAG=dev
fi
ENV_FILE=.env
PUBLISHED_IMAGE_REPO_BASE_DEFAULT=ghcr.io/nvidia/openshell
LOCAL_REGISTRY_CONTAINER=openshell-local-registry
LOCAL_REGISTRY_PORT=$(resolve_registry_port)
LOCAL_REGISTRY_ADDR=127.0.0.1:${LOCAL_REGISTRY_PORT}

if [ -n "${CI:-}" ] && [ -n "${CI_REGISTRY_IMAGE:-}" ]; then
  IMAGE_REPO_BASE_DEFAULT=${CI_REGISTRY_IMAGE}
elif [ "${MODE}" = "fast" ]; then
  IMAGE_REPO_BASE_DEFAULT=${LOCAL_REGISTRY_ADDR}/openshell
else
  IMAGE_REPO_BASE_DEFAULT=${LOCAL_REGISTRY_ADDR}/openshell
fi

IMAGE_REPO_BASE=${IMAGE_REPO_BASE:-${OPENSHELL_REGISTRY:-${IMAGE_REPO_BASE_DEFAULT}}}
REGISTRY_HOST=${OPENSHELL_REGISTRY_HOST:-${IMAGE_REPO_BASE%%/*}}
REGISTRY_NAMESPACE_DEFAULT=${IMAGE_REPO_BASE#*/}

if [ "${REGISTRY_NAMESPACE_DEFAULT}" = "${IMAGE_REPO_BASE}" ]; then
  REGISTRY_NAMESPACE_DEFAULT=openshell
fi

has_env_key() {
  local key=$1
  [ -f "${ENV_FILE}" ] || return 1
  grep -Eq "^[[:space:]]*(export[[:space:]]+)?${key}=" "${ENV_FILE}"
}

append_env_if_missing() {
  local key=$1
  local value=$2
  if has_env_key "${key}"; then
    return
  fi
  if [ -f "${ENV_FILE}" ] && [ -s "${ENV_FILE}" ]; then
    # Ensure file ends with newline before appending, but don't add extra blank line
    if [ "$(tail -c1 "${ENV_FILE}" | wc -l)" -eq 0 ]; then
      printf "\n" >>"${ENV_FILE}"
    fi
  fi
  printf "%s=%s\n" "${key}" "${value}" >>"${ENV_FILE}"
}

CLUSTER_NAME=${CLUSTER_NAME:-$(basename "$PWD")}
CLUSTER_NAME=$(normalize_name "${CLUSTER_NAME}")

if [ -n "${GATEWAY_PORT:-}" ]; then
  RESOLVED_GATEWAY_PORT=${GATEWAY_PORT}
elif [ "${MODE}" = "fast" ]; then
  RESOLVED_GATEWAY_PORT=$(pick_random_port)
else
  RESOLVED_GATEWAY_PORT=8080
fi

OPENSHELL_GATEWAY=${OPENSHELL_GATEWAY:-${CLUSTER_NAME}}
GATEWAY_PORT=${RESOLVED_GATEWAY_PORT}

append_env_if_missing "GATEWAY_PORT" "${GATEWAY_PORT}"
append_env_if_missing "OPENSHELL_GATEWAY" "${OPENSHELL_GATEWAY}"

export CLUSTER_NAME
export GATEWAY_PORT
export OPENSHELL_GATEWAY

is_local_registry_host() {
  [ "${REGISTRY_HOST}" = "127.0.0.1:${LOCAL_REGISTRY_PORT}" ] || \
  [ "${REGISTRY_HOST}" = "localhost:${LOCAL_REGISTRY_PORT}" ]
}

registry_reachable() {
  curl -4 -fsS --max-time 2 "http://127.0.0.1:${LOCAL_REGISTRY_PORT}/v2/" >/dev/null 2>&1 || \
    curl -4 -fsS --max-time 2 "http://localhost:${LOCAL_REGISTRY_PORT}/v2/" >/dev/null 2>&1
}

wait_for_registry_ready() {
  local attempts=${1:-20}
  local delay_s=${2:-1}
  local i

  for i in $(seq 1 "${attempts}"); do
    if registry_reachable; then
      return 0
    fi
    sleep "${delay_s}"
  done

  return 1
}

ensure_local_registry() {
  # Remove stale pull-through proxy containers.
  if "${CONTAINER_CMD}" inspect "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1; then
    local proxy_remote_url
    proxy_remote_url=$("${CONTAINER_CMD}" inspect "${LOCAL_REGISTRY_CONTAINER}" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | awk -F= '/^REGISTRY_PROXY_REMOTEURL=/{print $2; exit}' || true)
    if [ -n "${proxy_remote_url}" ]; then
      "${CONTAINER_CMD}" rm -f "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1 || true
    fi
  fi

  # If the container exists with a mismatched port binding, remove it so we
  # can recreate it on the resolved port.  This check uses HostConfig (works
  # on stopped containers) to avoid a bind-error on start.
  if "${CONTAINER_CMD}" inspect "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1; then
    local _existing_port
    _existing_port=$("${CONTAINER_CMD}" inspect "${LOCAL_REGISTRY_CONTAINER}" \
      --format '{{range $p, $b := .HostConfig.PortBindings}}{{if eq $p "5000/tcp"}}{{range $b}}{{.HostPort}}{{end}}{{end}}{{end}}' \
      2>/dev/null || true)
    if [ -n "${_existing_port}" ] && [ "${_existing_port}" != "${LOCAL_REGISTRY_PORT}" ]; then
      echo "Recreating local registry: old port ${_existing_port} → ${LOCAL_REGISTRY_PORT}" >&2
      "${CONTAINER_CMD}" rm -f "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1 || true
    fi
  fi

  if ! "${CONTAINER_CMD}" inspect "${LOCAL_REGISTRY_CONTAINER}" >/dev/null 2>&1; then
    "${CONTAINER_CMD}" run -d --restart=always --name "${LOCAL_REGISTRY_CONTAINER}" -p "${LOCAL_REGISTRY_PORT}:5000" registry:2 >/dev/null
  else
    if ! "${CONTAINER_CMD}" ps --filter "name=^${LOCAL_REGISTRY_CONTAINER}$" --filter "status=running" -q | grep -q .; then
      "${CONTAINER_CMD}" start "${LOCAL_REGISTRY_CONTAINER}" >/dev/null
    fi
  fi

  if wait_for_registry_ready 20 1; then
    return
  fi

  if registry_reachable; then
    return
  fi

  echo "Error: local registry is not reachable at ${REGISTRY_HOST}." >&2
  echo "       Ensure a registry is running on port ${LOCAL_REGISTRY_PORT} (e.g. ${CONTAINER_CMD} run -d --name openshell-local-registry -p ${LOCAL_REGISTRY_PORT}:5000 registry:2)." >&2
  "${CONTAINER_CMD}" ps -a >&2 || true
  "${CONTAINER_CMD}" logs "${LOCAL_REGISTRY_CONTAINER}" >&2 || true
  exit 1
}

REGISTRY_ENDPOINT_DEFAULT=${REGISTRY_HOST}
if is_local_registry_host; then
  if [ "${CONTAINER_CMD}" = "podman" ]; then
    REGISTRY_ENDPOINT_DEFAULT=host.containers.internal:${LOCAL_REGISTRY_PORT}
  else
    REGISTRY_ENDPOINT_DEFAULT=host.docker.internal:${LOCAL_REGISTRY_PORT}
  fi
fi

REGISTRY_INSECURE_DEFAULT=false
if is_local_registry_host; then
  REGISTRY_INSECURE_DEFAULT=true
fi

export OPENSHELL_REGISTRY_HOST=${OPENSHELL_REGISTRY_HOST:-${REGISTRY_HOST}}
export OPENSHELL_REGISTRY_ENDPOINT=${OPENSHELL_REGISTRY_ENDPOINT:-${REGISTRY_ENDPOINT_DEFAULT}}
export OPENSHELL_REGISTRY_NAMESPACE=${OPENSHELL_REGISTRY_NAMESPACE:-${REGISTRY_NAMESPACE_DEFAULT}}
export OPENSHELL_REGISTRY_INSECURE=${OPENSHELL_REGISTRY_INSECURE:-${REGISTRY_INSECURE_DEFAULT}}
export IMAGE_REPO_BASE
export IMAGE_TAG

if [ -n "${CI:-}" ] && [ -n "${CI_REGISTRY:-}" ] && [ -n "${CI_REGISTRY_USER:-}" ] && [ -n "${CI_REGISTRY_PASSWORD:-}" ]; then
  printf '%s' "${CI_REGISTRY_PASSWORD}" | "${CONTAINER_CMD}" login -u "${CI_REGISTRY_USER}" --password-stdin "${CI_REGISTRY}"
  export OPENSHELL_REGISTRY_USERNAME=${OPENSHELL_REGISTRY_USERNAME:-${CI_REGISTRY_USER}}
  export OPENSHELL_REGISTRY_PASSWORD=${OPENSHELL_REGISTRY_PASSWORD:-${CI_REGISTRY_PASSWORD}}
fi

if is_local_registry_host; then
  ensure_local_registry
fi

CONTAINER_NAME="openshell-cluster-${CLUSTER_NAME}"
VOLUME_NAME="openshell-cluster-${CLUSTER_NAME}"

if [ "${MODE}" = "fast" ]; then
  if "${CONTAINER_CMD}" inspect "${CONTAINER_NAME}" >/dev/null 2>&1 || "${CONTAINER_CMD}" volume inspect "${VOLUME_NAME}" >/dev/null 2>&1; then
    echo "Recreating cluster '${CLUSTER_NAME}' from scratch..."
    openshell gateway destroy --name "${CLUSTER_NAME}"
  fi
fi

if [ "${SKIP_IMAGE_PUSH:-}" = "1" ]; then
  echo "Skipping image push (SKIP_IMAGE_PUSH=1; images already in registry)."
elif [ "${MODE}" = "build" ] || [ "${MODE}" = "fast" ]; then
  tasks/scripts/cluster-push-component.sh gateway
fi

# Build the cluster image so it contains the latest Helm chart, manifests,
# and entrypoint from the working tree.  This ensures the k3s container
# always starts with the correct chart version.
if [ "${SKIP_CLUSTER_IMAGE_BUILD:-}" != "1" ]; then
  tasks/scripts/docker-build-image.sh cluster
fi

# In fast/build modes, use the locally-built cluster image rather than the
# remote distribution registry image.  The local image is built by
# `docker-build-image.sh cluster` and contains the bundled Helm chart and
# manifests from the current working tree.
if [ -z "${OPENSHELL_CLUSTER_IMAGE:-}" ]; then
  export OPENSHELL_CLUSTER_IMAGE="openshell/cluster:${IMAGE_TAG}"
fi

DEPLOY_CMD=(openshell gateway start --name "${CLUSTER_NAME}" --port "${GATEWAY_PORT}")

if [ -n "${GATEWAY_HOST:-}" ]; then
  DEPLOY_CMD+=(--gateway-host "${GATEWAY_HOST}")

  # Ensure the gateway host resolves from the current environment.
  # On Linux CI runners host.docker.internal is not set automatically
  # (it's a Docker Desktop feature). If the hostname doesn't resolve,
  # add it via the Docker bridge gateway IP.
  if ! getent hosts "${GATEWAY_HOST}" >/dev/null 2>&1; then
    DEFAULT_BRIDGE_NETWORK=$( [ "${CONTAINER_CMD}" = "podman" ] && echo "podman" || echo "bridge" )
    BRIDGE_IP=$("${CONTAINER_CMD}" network inspect "${DEFAULT_BRIDGE_NETWORK}" --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)
    if [ -n "${BRIDGE_IP}" ]; then
      echo "Adding /etc/hosts entry: ${BRIDGE_IP} ${GATEWAY_HOST}"
      echo "${BRIDGE_IP} ${GATEWAY_HOST}" >> /etc/hosts
    fi
  fi
fi

"${DEPLOY_CMD[@]}"

# Clear the fast-deploy state file so the next incremental deploy
# recalculates from scratch.  This prevents stale fingerprints from a
# prior session from masking changes that the bootstrap has already baked
# into the freshly pushed images.
DEPLOY_FAST_STATE_FILE=${DEPLOY_FAST_STATE_FILE:-.cache/cluster-deploy-fast.state}
rm -f "${DEPLOY_FAST_STATE_FILE}"

echo ""
echo "Cluster '${CLUSTER_NAME}' is ready."
