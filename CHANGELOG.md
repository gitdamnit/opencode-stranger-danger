# Changelog

## 0.2.0 (unreleased)

Security hardening and OpenCode V2 migration. Not yet published.

### Security fixes

- **File reads never modify files.** The pre-read hook no longer rewrites source
  files on disk when it detects a secret. Redaction now happens at the supported
  V2 result/request boundaries.
- **Effective outbound protection.** Migrated to V2 `session.prompt`,
  `session.context`, and `session.compaction` hooks so prompts, tool results,
  compaction transcripts, and auxiliary model requests are redacted *before*
  transmission. The V1 `event` handler only audited after the fact.
- **Chunk-safe output scanning.** Tool output is no longer truncated at 1 MB.
  Large content is scanned in overlapping windows; un-inspectable content fails
  closed with an explicit marker.
- **No raw secrets in CLI output.** `sd scan --json` and human output report safe
  metadata (rule, description, source, line/column, fingerprint, redaction token).
- **Safe `sd redact`.** Atomic write (temp + fsync + rename). No plaintext
  `.backup` in the working tree by default; opt in with `--backup`/`--backup-dir`,
  which writes a `0600` backup outside the tree.
- **Critical regex fix.** RE2/Pcre inline-flag groups (`(?-i:…)`, `(?i:…)`,
  `(?s:…)`), POSIX classes, and `\z` — which crashed `new RegExp` at import time
  and made the whole engine unusable — are translated to valid JavaScript.
- **Performance.** Whole-content keyword prefilter; ~500× faster on large inputs.

### OpenCode V2 migration

- Replaced `@opencode-ai/plugin` with `@opencode/plugin` (peer dependency).
- Plugin is now `Plugin.define({ id: "gitdamnit.stranger-danger", setup(ctx) })`.
- Five tools migrated to JSON Schema and `ctx.tool.transform`: `sd_status`,
  `sd_audit`, `sd_allowlist_add`, `sd_allowlist_show`, `sd_scan`.
- Hooks migrated: `tool.execute.before/after`, `session.prompt`,
  `session.context`, `session.compaction`, `event.subscribe`.
- Config example updated from `plugin` to `plugins`.

### Audit logging and multi-session safety

- Project-scoped audit path under `.opencode/state/`; hooks require an explicit
  per-project path (no shared mutable process-global state).
- Session IDs recorded where available; audit files are `0600`, directories `0700`.
- Size-bounded rotation to `.1`/`.2`/`.3` (never truncates records away).
- Runtime state is Git-ignored; the previously tracked audit file is untracked
  but preserved on disk.

### Reliability, tests, packaging, CI

- Fixed test discovery (referenced a non-existent `tests/integration.ts`;
  root-level suites were never run). Full suite now runs and passes.
- Added regression coverage for read-only file access, outbound redaction,
  boundary-crossing secrets, large outputs, secret-free JSON, safe backups,
  allowlist behavior, audit integrity, and V2 hook/tool wiring.
- `zod` import removed (was undeclared); `@opencode/plugin` declared.
- CI rewritten to run typecheck, lint, build, unit, integration, security, and
  package-validation steps on Node 22. Added `eslint.config.js` and
  `scripts/verify-package.mjs`.

## 0.1.0 (2026-05-08)

Initial release.

### Features

- Three-layer secret scanning: file-level, context-level, output-level
- ~160 rules vendored from gitleaks (MIT)
- ~12 clean-room additions for AI/ML providers (Groq, DeepSeek, Replicate, ElevenLabs, W&B, LangSmith, LangFuse, Supabase, Vercel, MongoDB, PostgreSQL, Redis)
- 3 entropy-based detectors (Base64, Hex, Alphanumeric)
- OpenCode plugin with hooks: `tool.execute.before`, `experimental.session.compacting`, `tool.execute.after`, `event`
- OpenCode tools: `sd_status`, `sd_audit`, `sd_allowlist_add`, `sd_allowlist_show`, `sd_scan`
- Standalone CLI: `sd scan`, `sd redact`, `sd audit`, `sd rules`, `sd allowlist`
- Deterministic SHA-256 fingerprinting for redaction tokens
- JSONL audit log (never stores secret values)
- TOML allowlist support (by fingerprint, ruleId, path, regex)
- Zero runtime dependencies
