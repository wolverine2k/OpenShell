<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Network Access Rules

Every outbound connection from a sandbox passes through NemoClaw's transparent
proxy. Nothing leaves the sandbox directly. The proxy identifies which binary
initiated the connection, evaluates the active policy, and decides what happens
next.

## How the Proxy Evaluates Connections

Each outbound connection resolves to one of two outcomes:

| Outcome | When it applies | What happens |
|---|---|---|
| Allow | A `network_policies` entry matches the destination host and the calling binary. | Traffic flows directly to the destination. The process uses its own credentials. |
| Deny | No network policy matches the destination and binary pair. | The connection is blocked. The calling process receives a 403 or connection reset. |

:::{note}
`inference.local` is a special case. It is an explicit sandbox-local inference
endpoint, not a destination you allow through `network_policies`. Userland code
calls `https://inference.local`, and the proxy routes that traffic through the
inference router instead of sending it to the public network.
:::

```{mermaid}
flowchart TD
    A[Outbound connection from sandbox] --> B{Target is inference.local?}
    B -- Yes --> C[Handle locally as inference traffic]
    B -- No --> D[Resolve calling binary]
    D --> E{"Network policy matches\nendpoint + binary?"}
    E -- Yes --> F[Allow: forward directly\nto destination]
    E -- No --> G[Deny: 403]
```

## Agent Traffic vs. Userland Traffic

This is the most important distinction in NemoClaw's network model.

**Agent traffic** is the coding agent calling its own upstream API. That traffic
must match a `network_policies` entry because the policy declares both the
destination (for example, `api.anthropic.com:443`) and the binary (for example,
`/usr/local/bin/claude`). The proxy allows it through directly.

**Userland traffic** is code that the agent writes: Python scripts, test
harnesses, notebooks, web apps, and automation tools. If that code needs model
access without direct provider credentials, it should call
`https://inference.local`. NemoClaw then injects the provider credentials and
routes the request to the configured backend.

If userland code tries to call `api.openai.com`, `api.anthropic.com`, or another
external inference host directly, that is treated like any other outbound
network request and must match `network_policies`.

## Structure of a Network Policy Entry

Each entry in the `network_policies` section pairs a set of endpoints with a set
of binaries. Only the listed binaries can connect to the listed endpoints:

```yaml
network_policies:
  my_rule:
    name: my-rule
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/local/bin/my-agent
```

The key (`my_rule`) is a logical name for reference. The `name` field is the
human-readable label that appears in logs and the NemoClaw Terminal.

## Endpoints

Each endpoint entry controls access to a single host-port combination. Refer to
[Endpoint Object](../reference/policy-schema.md#endpoint-object) for the full
field reference.

The `access` field provides presets: `full` (all methods), `read-only` (`GET`,
`HEAD`, `OPTIONS`), or `read-write` (`GET`, `HEAD`, `OPTIONS`, `POST`, `PUT`,
`PATCH`).

### Custom Rules

When access presets are not granular enough, define explicit allow rules. Each
rule specifies a method and a path pattern:

```yaml
endpoints:
  - host: github.com
    port: 443
    protocol: rest
    tls: terminate
    enforcement: enforce
    rules:
      - allow:
          method: GET
          path: /**/info/refs*
      - allow:
          method: POST
          path: /**/git-upload-pack
```

This example allows Git fetch operations while blocking push operations. Path
patterns use glob syntax.

If a request does not match any rule, it is denied (in `enforce` mode) or
logged (in `audit` mode).

## Binaries

The `binaries` list specifies which executables are permitted to use the
endpoint. Each entry has a `path` field that the proxy matches against the
calling process.

The proxy resolves the calling binary through several mechanisms, evaluated in
order:

| Match type | Example | Description |
|---|---|---|
| Exact path | `/usr/local/bin/claude` | Matches the binary at exactly this path. |
| Ancestor process | `/usr/local/bin/claude` | Matches if any ancestor in the process tree has this path. |
| Cmdline path | `/usr/local/bin/opencode` | Matches interpreted entrypoints where the `exe` link points to the interpreter. |
| Glob pattern | `/sandbox/.vscode-server/**` | Matches any executable under the directory tree. |

## L7 Inspection

To inspect HTTPS traffic at the HTTP level, you need both `protocol: rest` and
`tls: terminate` on the endpoint:

```yaml
endpoints:
  - host: api.example.com
    port: 443
    protocol: rest
    tls: terminate
    enforcement: enforce
    access: full
```

With both fields set, the proxy terminates the TLS connection, decrypts the
HTTP request, evaluates it against the `access` preset or custom `rules`, and
re-encrypts before forwarding to the destination.

:::{warning}
Without `tls: terminate` on port 443, the proxy cannot decrypt the traffic. L7
rules are not evaluated because the HTTP payload is encrypted.
:::

## Enforcement Modes

Each endpoint can operate in one of two enforcement modes:

| Mode | Behavior on violation |
|---|---|
| `enforce` | Blocks the request and returns HTTP 403 to the calling process. The violation is logged. |
| `audit` | Logs the violation but forwards the traffic to the destination. The agent is not interrupted. |

## Next Steps

- [Write Sandbox Policies](policies.md): the iterative workflow for authoring,
  testing, and updating policies.
- {doc}`../inference/index`: how `inference.local` fits into the network model.
