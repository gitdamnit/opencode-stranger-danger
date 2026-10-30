# Changelog

## 0.2.1 (2026-10-29)

Packaging and npm-identity fix. The 0.2.0 source was distributed only as a
GitHub release; it was never installable from npm.

### Fixed
- **Restored the published npm package identity.** `package.json` named the
  package `@gitdamnit/stranger-danger`, which has never existed on npm, so
  `npm install` could not resolve it. The package is again
  `@gitdamnit/opencode-stranger-danger`, the name published since 0.1.0.
- **`npm run verify:package` no longer hardcodes the package name.** It reads
  the name from `package.json`, so packaging validation cannot drift from what
  is actually published. The previous hardcoding is what made the packed-artifact
  check fail as soon as the name was corrected.

### Changed
- **npm publication is manual and OIDC-based.** `.github/workflows/publish.yml`
  now runs only on `workflow_dispatch`, checks out and verifies the release tag,
  and publishes through npm Trusted Publishing instead of an `NPM_TOKEN` secret.

## 0.2.0 (2026-10-16)

Security hardening and OpenCode V2 migration. Published as a GitHub release;
npm publication of `@gitdamnit/opencode-stranger-danger` is pending registry setup
(install from the repository in the meantime).

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
- **Auxiliary requests are now covered.** `session.context` only runs for the
  agent loop. The plugin now also registers `session.generate` (transient
  `ctx.session.generate` requests) and `session.title` (title generation), which
  had been sent uninspected.
- **Tool error metadata is redacted.** `Tool.Error.metadata` is surfaced to the
  model alongside the message; it is now scanned like the rest of the result.
- **Structured redaction is cycle-safe and fails closed.** A self-referential
  tool output previously overflowed the stack; the thrown error was swallowed by
  the hook, leaving the *entire* result — including plain string secrets —
  unredacted. Cyclic and over-deep (>32 levels) branches now fail closed with an
  explicit marker instead.
- **V2 event-stream audit actually fires.** The handler filtered on
  `type.startsWith("message")`, but every V2 event is namespaced `session.*`
  (`session.text.ended`, `session.tool.success`, …), so it never audited anything.
  It now consumes the real event shapes (skipping chatty `*.delta` frames).
- **`sd_scan` input is bounded** (8 MiB) so a model-invoked scan cannot exhaust
  memory or hang the server.

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

### Independence & interoperability standard

- Confirmed and documented plugin independence: no cross-plugin imports, no
  shared database/configuration, no required initialization order, no companion
  dependency. Tools are `sd_`-namespaced; storage and config are namespaced.
- Hardened hook callbacks to never throw on malformed/unexpected events, so a
  broken companion or bad event cannot cascade.
- Documented the ordering-independent guarantee (the `session.context` hook is
  the backstop) and the single optional, read-only, semver-versioned interop
  surface (`@gitdamnit/opencode-stranger-danger/engine`).
- Removed a stale reference to the retired CheapCode project from
  `scripts/write_fixture.ts`; it now writes only inside this repository.
- Added an independence test suite (isolated instances, session isolation,
  no-order-dependency, failure isolation, reload/cleanup, companion-absent
  behavior, absence of cross-plugin coupling).

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
- **Root `index.js` entrypoint.** OpenCode resolves a plugin *directory* to
  `<directory>/index.{ts,js}` and ignores `main`/`exports`, so a
  `{ "package": "/path/to/stranger-danger" }` entry previously failed to load with
  `Plugin entrypoint not found` — the session ran unprotected. The package now
  ships a root `index.js` (also published via `files`).
- Added `tests/security-coverage.test.ts` covering the fixes above: auxiliary
  request hooks, tool-error metadata, cycle/over-depth fail-closed behavior,
  real V2 event detection, injected-limit bounds for the oversized/timeout
  branches, the `sd_scan` cap, and two-instance audit isolation.
- Verified on the real runtime (OpenCode `2.0.21`, isolated server + disposable
  project + loopback mock provider): control run transmits the synthetic secret;
  plugin run does not, emits a redaction token, and writes a secret-free audit
  record.

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
