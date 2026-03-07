<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Terminal

NemoClaw Terminal is a terminal dashboard that displays sandbox status and live activity in a single view. Use it to monitor agent behavior, diagnose blocked connections, and observe `inference.local` traffic in real time.

```console
$ nemoclaw term
```

## Sandbox Status

The status pane at the top of the dashboard displays the following sandbox metadata:

- Name and phase (`Provisioning`, `Ready`, `Error`)
- Image running in the sandbox
- Providers attached and their available credentials
- Age since creation
- Port forwards currently active

A phase other than `Ready` indicates the sandbox is still initializing or has encountered an error. Inspect the logs pane for details.

## Live Log Stream

The logs pane streams activity in real time. Outbound connections, policy decisions, and inference routing events appear as they occur.

Log entries originate from two sources:

- sandbox: The sandbox supervisor (proxy decisions, policy enforcement, SSH connections, process lifecycle).
- gateway: The control plane (sandbox creation, phase changes, policy distribution).

Press `f` to enable follow mode and auto-scroll to new entries.

## Diagnosing Blocked Connections

Entries with `action=deny` indicate connections blocked by policy:

```
22:35:19 sandbox INFO CONNECT action=deny dst_host=registry.npmjs.org dst_port=443
```

Each deny entry contains the following fields:

| Field | Description |
|---|---|
| `action=deny` | Connection was blocked by the network policy. |
| `dst_host` | Destination host the process attempted to reach. |
| `dst_port` | Destination port (typically 443 for HTTPS). |
| `src_addr` | Source address inside the sandbox. |
| `policy` | Policy rule that was evaluated, or `-` if no rule matched. |

To resolve a blocked connection:

1. Add the host to the network policy if the connection is legitimate. Refer to {doc}`../safety-and-privacy/policies` for the iteration workflow.
2. Leave it blocked if the connection is unauthorized.

## Diagnosing Inference Traffic

Userland inference now goes through the explicit `inference.local` endpoint.
When code inside the sandbox uses `https://inference.local`, look for CONNECT
entries targeting `inference.local` plus follow-up routing logs.

This indicates:

- The application intentionally used the sandbox-local inference endpoint.
- The proxy TLS-terminated the tunnel and inspected the HTTP request.
- NemoClaw matched a supported inference API pattern and routed it to the
  cluster-configured backend.

If those requests fail, the most common causes are:

- cluster inference is not configured yet
- the request path does not match a supported inference API pattern
- the upstream provider credentials or model configuration are invalid

## Filtering and Navigation

The dashboard provides filtering and navigation controls:

- Press `s` to filter logs by source. Display only `sandbox` logs (policy decisions) or only `gateway` logs (lifecycle events).
- Press `f` to toggle follow mode. Auto-scroll to the latest entries.
- Press `Enter` on a log entry to open the detail view with the full message.
- Use `j` / `k` to navigate up and down the log list.

## Keyboard Shortcuts

The following keyboard shortcuts are available in the terminal dashboard.

| Key | Action |
|---|---|
| `j` / `k` | Navigate down / up in the log list. |
| `Enter` | Open detail view for the selected entry. |
| `g` / `G` | Jump to top / bottom. |
| `f` | Toggle follow mode (auto-scroll to new entries). |
| `s` | Open source filter (sandbox, gateway, or all). |
| `Esc` | Return to the main view / close detail view. |
| `q` | Quit. |

## Related Topics

For deeper dives into topics covered by the terminal dashboard, refer to the following guides.

- Blocked connections: Follow {doc}`../safety-and-privacy/policies` to pull the current policy, add the missing endpoint, and push an update without restarting the sandbox.
- Inference routing: Refer to {doc}`../safety-and-privacy/network-access-rules` for the distinction between direct network traffic and `inference.local` traffic.
- Troubleshooting: Refer to {doc}`../troubleshooting` for troubleshooting tips and diagnostics.
