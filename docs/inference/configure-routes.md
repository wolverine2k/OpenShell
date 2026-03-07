<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Configure Cluster Inference

NemoClaw no longer manages multiple inference routes. Instead, each cluster has
one managed inference backend behind `https://inference.local`.

That configuration consists of two values:

- a provider record name
- a model ID

## Step 1: Create a Provider

Create a provider that holds the backend credentials you want NemoClaw to use.

```console
$ nemoclaw provider create --name nvidia-prod --type nvidia --from-existing
```

You can also use `openai` or `anthropic` providers.

## Step 2: Set Cluster Inference

Point `inference.local` at that provider and choose the model to use:

```console
$ nemoclaw cluster inference set \
    --provider nvidia-prod \
    --model meta/llama-3.1-8b-instruct
```

This creates or replaces the cluster-managed inference configuration.

## Step 3: Verify the Active Config

```console
$ nemoclaw cluster inference get
provider: nvidia-prod
model:    meta/llama-3.1-8b-instruct
version:  1
```

## Step 4: Update Part of the Config

Use `update` when you want to change only one field:

```console
$ nemoclaw cluster inference update --model meta/llama-3.3-70b-instruct
```

Or switch providers without repeating the current model manually:

```console
$ nemoclaw cluster inference update --provider openai-prod
```

## Use It from a Sandbox

Once cluster inference is configured, userland code inside any sandbox can call
`https://inference.local` directly:

```python
from openai import OpenAI

client = OpenAI(base_url="https://inference.local/v1", api_key="dummy")

response = client.chat.completions.create(
    model="anything",
    messages=[{"role": "user", "content": "Hello"}],
)
```

The client-supplied model is ignored for generation requests. NemoClaw rewrites
it to the cluster-configured model before forwarding upstream.

## Good to Know

- Cluster-scoped: every sandbox in the cluster sees the same `inference.local`
  backend.
- No route CRUD: `nemoclaw inference create/update/delete/list` is gone.
- No policy allowlist: sandbox policies do not contain `inference.allowed_routes`
  anymore.
- HTTPS only: `inference.local` is intercepted only for HTTPS traffic.

## Next Steps

- {doc}`index`: understand the interception flow and supported API patterns.
- {doc}`../sandboxes/providers`: create and manage provider records.
- {doc}`../reference/cli`: see the CLI reference for `cluster inference`
  commands.
