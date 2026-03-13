---
name: generate-cli-reference
description: Regenerate the CLI reference markdown from source definitions and deploy it to documentation targets. Use when CLI commands, flags, or descriptions change and the reference docs need updating. Trigger keywords - generate cli reference, regenerate cli docs, update cli reference, cli markdown, cli-reference, docs cli-reference.
---

# Generate CLI Reference

Regenerate the auto-generated CLI reference markdown and deploy it to all documentation targets.

## When to Use

Run this after any change to CLI commands, flags, or doc comments in `crates/navigator-cli/src/main.rs`. The generated reference is derived from clap's command tree, so source doc comments are the single source of truth.

## Prerequisites

- Rust toolchain available (`cargo` on PATH, or use `mise exec --`)
- The project compiles successfully

## Steps

### 1. Build and run the generator

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo run --bin openshell -- docs cli-reference > /tmp/cli-reference-generated.md
```

Or with mise:

```bash
mise exec -- cargo run --bin openshell -- docs cli-reference > /tmp/cli-reference-generated.md
```

### 2. Deploy to documentation targets

Copy the generated file to both locations:

```bash
cp /tmp/cli-reference-generated.md .agents/skills/openshell-cli/cli-reference-generated.md
cp /tmp/cli-reference-generated.md docs/reference/cli-generated.md
```

Note: `.claude/skills/` is a symlink to `.agents/skills/`, so the first copy covers both.

### 3. Verify

Spot-check that descriptions end with periods and the command tree looks correct:

```bash
head -60 .agents/skills/openshell-cli/cli-reference-generated.md
```

## Target Files

| File | Purpose |
|------|---------|
| `.agents/skills/openshell-cli/cli-reference-generated.md` | Agent skill reference (also serves `.claude/skills/` via symlink) |
| `docs/reference/cli-generated.md` | User-facing documentation site |

## Key Source Files

| File | Purpose |
|------|---------|
| `crates/navigator-cli/src/main.rs` | CLI definitions (commands, flags, doc comments) |
| `crates/navigator-cli/src/cli_reference.rs` | Markdown generator logic |

## Notes

- The generator is a hidden subcommand (`openshell docs cli-reference`) that introspects clap's command tree at runtime.
- Clap strips trailing periods from single-line doc comments; the generator restores them via `ensure_period()`.
- The generated files contain a `<!-- Do not edit manually -->` header. Always regenerate rather than hand-editing.
