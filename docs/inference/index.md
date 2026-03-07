<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Inference Routing

NemoClaw exposes inference through a single explicit endpoint inside every
sandbox: `https://inference.local`. Userland code sends OpenAI- or
Anthropic-compatible requests there, and NemoClaw routes them to the
cluster-configured backend.

:::{note}
Inference routing applies to userland traffic: scripts, tests, notebooks, and
applications the agent writes inside the sandbox. The agent's own API traffic
still goes directly through `network_policies`. See
{doc}`/safety-and-privacy/network-access-rules`.
:::

## How It Works

When code inside a sandbox calls `https://inference.local`, the sandbox proxy:

1. Intercepts the HTTPS `CONNECT` tunnel to `inference.local`.
2. TLS-terminates the client side using the sandbox CA.
3. Parses the HTTP request inside the tunnel.
4. Detects the inference protocol from the method and path.
5. Forwards the request to the configured backend with the provider's
   credentials.
6. Rewrites the `model` field on generation requests to the cluster-configured
   model.

There is no implicit catch-all routing for arbitrary hosts anymore. If code
tries to call `api.openai.com`, `api.anthropic.com`, or any other host directly,
that traffic is evaluated only by `network_policies`.

```{mermaid}
sequenceDiagram
    participant Code as Userland Code
    participant Proxy as Sandbox Proxy
    participant Router as Inference Router
    participant Backend as Configured Backend

    Code->>Proxy: CONNECT inference.local:443
    Proxy-->>Code: 200 Connection Established
    Proxy->>Proxy: TLS terminate
    Code->>Proxy: POST /v1/chat/completions
    Proxy->>Router: route inferred protocol
    Router->>Backend: forward with injected auth
    Backend-->>Router: response
    Router-->>Proxy: response
    Proxy-->>Code: HTTP response over tunnel
```

## Supported API Patterns

| Pattern | Method | Path |
|---|---|---|
| OpenAI Chat Completions | `POST` | `/v1/chat/completions` |
| OpenAI Completions | `POST` | `/v1/completions` |
| OpenAI Responses | `POST` | `/v1/responses` |
| Anthropic Messages | `POST` | `/v1/messages` |
| Model Discovery | `GET` | `/v1/models` |
| Model Discovery | `GET` | `/v1/models/*` |

Requests to `inference.local` that do not match one of these patterns are
denied.

## Key Properties

- Explicit endpoint: routing happens only through `inference.local`.
- No sandbox API keys: credentials come from the configured provider record.
- Single cluster config: one provider + one model define sandbox inference.
- Provider-agnostic: OpenAI, Anthropic, and NVIDIA providers all work through
  the same endpoint.
- Hot-refresh: provider credential changes and cluster inference updates are
  picked up without recreating sandboxes.

## Next Steps

- {doc}`configure-routes`: configure the cluster-wide backend behind
  `inference.local`.
- {doc}`/safety-and-privacy/network-access-rules`: understand direct agent
  traffic vs. `inference.local` traffic.
