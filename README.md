![strangerDanger logo](./strangerdanger2.jpeg)

# @gitdamnit/stranger-danger

Secret and PII redaction guard for AI coding agents.

[![npm version](https://img.shields.io/npm/v/@gitdamnit/stranger-danger.svg)](https://www.npmjs.com/package/@gitdamnit/stranger-danger)
[![license](https://img.shields.io/npm/l/@gitdamnit/stranger-danger.svg)](LICENSE)
[![node](https://img.shields.io/node/v/@gitdamnit/stranger-danger.svg)](https://nodejs.org)

## The Problem

Every secret scanner checks your files. None check what goes into the LLM's context window. A secret can be clean in your repo and still get sent to a cloud API inside a prompt, checkpoint, or shell summary. strangerDanger operates at the OpenCode V2 request boundaries to catch what others miss.

## How It Works — Protection at the V2 boundaries

strangerDanger registers only documented V2 hooks. Reading a file never rewrites it.

| Boundary | Hook | What it protects |
| --- | --- | --- |
| Incoming prompt | `session.prompt` | User prompts, before durable admission |
| Tool results | `tool.execute.after` | `read`/`bash`/`grep`/`fetch` output before it reaches the model |
| Assembled request | `session.context` | System instructions, messages, tool-call inputs, tool results, auxiliary requests |
| Checkpoint compaction | `session.compaction` | The transcript being summarized, plus a plugin-provided summary |
| File inspection | `tool.execute.before` | Read-only detection + audit; **never writes to disk** |
| Event stream | `event.subscribe` | Detection/audit only (observational; cannot prevent transmission) |

All outgoing content is scanned with a **bounded, chunk-safe** scanner: large
outputs are fully covered (secrets that straddle a window boundary are still
found), and content that cannot be inspected fails **closed** with an explicit
marker instead of leaking.

## Installation

### OpenCode V2 plugin

Add to your `opencode.jsonc` (`plugins`, not the V1 `plugin` key):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": ["@gitdamnit/stranger-danger"]
}
```

The plugin requires the V2 runtime and `@opencode/plugin` (peer dependency).

### Standalone CLI

```bash
npm install -g @gitdamnit/stranger-danger
```

### Use with envsitter-guard

strangerDanger and [envsitter-guard](https://github.com/boxpositron/envsitter-guard) are complementary:
- envsitter-guard blocks `.env*` file reads entirely
- strangerDanger scans everything else and protects the model context

## Quick Start

### CLI

```bash
sd scan .                    # Scan current directory
sd scan src/config.ts        # Scan a single file
sd scan - < file.txt         # Scan stdin
sd scan . --json             # Machine-readable output (never contains raw secrets)

sd redact src/config.ts                  # Atomic in-place redaction, no plaintext backup
sd redact src/config.ts --backup         # Keep a 0600 backup outside the working tree
sd redact src/config.ts --backup-dir ~/bak

sd audit                     # Show audit log (no raw secrets)
sd rules                     # List all active rules
sd version
```

Every `scan`/`sd_scan` result reports **safe metadata only** — rule ID,
description, source, line/column, fingerprint, and the redaction token. Raw
matched secrets are never printed, logged, or written to the audit log.

## Detection Rules

- 221 rules vendored from gitleaks (MIT), translated to valid JavaScript regex
- 12 clean-room additions for AI/ML providers (Groq, DeepSeek, Replicate, ElevenLabs, W&B, LangSmith, LangFuse, Supabase, Vercel, and DB connection strings)
- 3 entropy-based detectors (Base64, Hex, Alphanumeric)

### Key Providers Covered

| Category | Providers |
|----------|-----------|
| Cloud | AWS, GCP, Azure, Alibaba, DigitalOcean, Heroku, Cloudflare |
| AI/ML | OpenAI, Anthropic, Groq, DeepSeek, Cohere, HuggingFace, Replicate, ElevenLabs |
| Version Control | GitHub, GitLab, Bitbucket |
| Communication | Slack, Discord, Telegram, Twilio, SendGrid, Mailgun |
| Payment | Stripe, Square, PayPal, Coinbase, Plaid |
| Databases | MongoDB, PostgreSQL, Redis (connection strings) |
| Generic | Private keys, JWTs, high-entropy strings |

## OpenCode Plugin Tools

- `sd_status` — Show rule count, findings, audit log path
- `sd_audit` — Show audit log with timestamps and rule IDs
- `sd_allowlist_add` — Add allowlist entry (also available as `sd allowlist add`)
- `sd_allowlist_show` — Show current allowlist
- `sd_scan` — Manually scan content (secret-free output)

## Allowlist

Create `.strangerdanger-allowlist.toml` in your project root:

```toml
[[entries]]
description = "Known test key"
fingerprint = "a3f7b2c1"

[[entries]]
description = "Ignore generic-api-key in test files"
ruleId = "generic-api-key"
path = "test/"
```

Entry types: `fingerprint`, `ruleId`, `path`, `regex`. Invalid regexes are
rejected on write and skipped on read.

## Audit Log

Location: `<project>/.opencode/state/strangerdanger-audit.jsonl` (project- and
session-scoped; ignored by Git).

- One JSON object per line; records rule ID, description, source, fingerprint,
  optional session ID and file path. **Never stores the secret value.**
- Written with `O_APPEND` so concurrent writers interleave whole records.
- Files are `0600`; the containing directory is `0700`.
- Grows to 10 MB, then rotates to `.1`, `.2`, `.3` (records are renamed, never
  truncated away).

## Security guarantees and known limitations

Guaranteed:

- Reading a file through the plugin **never modifies it** on disk.
- Tool results, assembled model requests, compaction transcripts, and prompts are
  redacted before transmission through the session pipeline.
- No raw secret is emitted by the CLI or the audit log.
- `sd redact` writes atomically and creates **no** plaintext backup unless you
  explicitly ask for one.

Not guaranteed (documented, by design):

- Provider-native **WebSocket** traffic that bypasses the session HTTP pipeline
  is not covered.
- The V2 event stream is observational (post-admission), so `event.subscribe`
  cannot prevent disclosure; it only audits.
- Structured output/metadata is redacted by replacing string leaves; exotic
  object types are left untouched to avoid corruption.
- Content larger than the scanner's hard ceiling fails closed with a marker
  rather than being partially inspected.

## Architecture

```
src/engine/     → Core detection engine (zero OpenCode deps)
src/plugin/     → OpenCode V2 plugin (hooks, transforms, tools)
src/cli/        → Standalone CLI (sd binary)
scripts/        → Rule compiler, package validation
```

The detection engine is decoupled from OpenCode: the standalone `sd` binary and
the plugin share `src/engine` and nothing else. Runtime dependency on
`@opencode/plugin` is a peer dependency, loaded only when the plugin entry is
imported.

## Development

```bash
npm install          # Install dependencies
npm run build:rules  # Compile gitleaks TOML → TypeScript
npm run typecheck    # Type check
npm run lint         # Lint
npm run build        # Build
npm test             # Full test suite
npm run test:security
npm run verify:package   # Pack, install into a temp dir, exercise the artifact
```

### Adding New Rules

Edit `scripts/compile-rules.ts` to add clean-room rules. The gitleaks TOML is
compiled automatically at build time; RE2/Pcre constructs (`(?i:…)`, `(?-i:…)`,
`(?s:…)`, POSIX classes, `\z`) are translated to plain JavaScript regex.

## Attribution

- **gitleaks/gitleaks** (MIT) — Secret detection rules vendored from `config/gitleaks.toml`. https://github.com/gitleaks/gitleaks
- **Yelp/detect-secrets** (Apache-2.0) — Shannon entropy detection approach referenced for high-entropy string detectors. Clean-room TypeScript implementation. https://github.com/Yelp/detect-secrets
- **boxpositron/envsitter-guard** (MIT) — Complementary plugin. https://github.com/boxpositron/envsitter-guard

## License

MIT. See LICENSE.
