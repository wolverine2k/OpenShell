<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Write Sandbox Policies

This guide covers how to author, iterate, and manage sandbox policies that
control what an agent can do inside a NemoClaw sandbox. You will learn to
create sandboxes with custom policies, monitor denied traffic to discover
missing rules, and push policy updates without restarting the sandbox.

## Policy Structure

A policy is a YAML document with four top-level sections. Static fields
(`filesystem_policy`, `landlock`, `process`) are locked at sandbox creation and
require recreation to change. The dynamic field (`network_policies`) is
hot-reloadable on a running sandbox.

```yaml
version: 1

# --- STATIC FIELDS (require sandbox recreation to change) ---

filesystem_policy:
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

# --- DYNAMIC FIELD (hot-reloadable on a running sandbox) ---

network_policies:
  claude_api:
    endpoints:
      - host: api.anthropic.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/local/bin/claude
      - path: /usr/bin/node
```

Refer to the [Policy Schema Reference](../reference/policy-schema.md) for every
field, type, and default value.

:::{note}
Inference routing is configured separately with `nemoclaw cluster inference
set/get/update`. It is no longer part of the sandbox policy YAML.
:::

## Default Policy

NemoClaw ships a built-in default policy designed for Claude Code. It covers
Claude's API endpoints, telemetry hosts, GitHub access, and VS Code marketplace
traffic out of the box.

| Agent | Default policy coverage | What you need to do |
|---|---|---|
| Claude Code | Full | Nothing: works out of the box |
| OpenCode | Partial | Add `opencode.ai` and any extra binaries or endpoints it uses. |
| Codex | None | Provide a custom policy with OpenAI endpoints and Codex binary paths. |

## Create a Sandbox with a Custom Policy

Pass a policy YAML file when creating the sandbox:

```console
$ nemoclaw sandbox create --policy ./my-policy.yaml --keep -- claude
```

The `--keep` flag keeps the sandbox running after the initial command exits,
which is useful when you plan to iterate on the policy.

To avoid passing `--policy` every time, set a default policy with an
environment variable:

```console
$ export NEMOCLAW_SANDBOX_POLICY=./my-policy.yaml
$ nemoclaw sandbox create --keep -- claude
```

## The Policy Iteration Loop

Policy authoring is iterative. Start with a minimal policy, observe what the
agent needs, and refine the rules until everything works.

```{mermaid}
flowchart TD
    A[1. Create sandbox with initial policy] --> B[2. Monitor logs for denied actions]
    B --> C[3. Pull current policy]
    C --> D[4. Modify the policy YAML]
    D --> E[5. Push updated policy]
    E --> F[6. Verify the new revision loaded]
    F --> B
```

### Step 1: Create the Sandbox with Your Initial Policy

```console
$ nemoclaw sandbox create --policy ./my-policy.yaml --keep -- claude
```

### Step 2: Monitor Logs for Denied Actions

In a second terminal, tail the sandbox logs and look for `action=deny` entries:

```console
$ nemoclaw sandbox logs <name> --tail --source sandbox
```

Each deny entry shows the blocked host, port, calling binary, and reason.

### Step 3: Pull the Current Policy

```console
$ nemoclaw sandbox policy get <name> --full > current-policy.yaml
```

### Step 4: Modify the Policy YAML

Common changes include:

- Adding endpoints to `network_policies`
- Adding binary paths to existing endpoint rules
- Creating new named policy entries for new destinations
- Adjusting `access` levels or adding custom `rules`

### Step 5: Push the Updated Policy

```console
$ nemoclaw sandbox policy set <name> --policy current-policy.yaml --wait
```

### Step 6: Verify the New Revision Loaded

```console
$ nemoclaw sandbox policy list <name>
```

Check that the latest revision shows status `loaded`.

## Safety Properties

**Last-known-good.** If a new policy revision fails validation, the previous
successfully loaded policy stays active.

**Idempotent.** Submitting the same policy content again does not create a new
revision.

## Next Steps

- [Network Access Rules](network-access-rules.md): how the proxy evaluates
  connections, endpoint allowlists, binary matching, and enforcement modes.
- {doc}`../inference/index`: how private inference works through
  `inference.local`.
