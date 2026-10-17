# Product Requirements

## Project Identity

**Name:** strangerDanger (`@gitdamnit/stranger-danger`)
**Repository:** https://github.com/gitdamnit/opencode-stranger-danger
**Licence:** MIT
**Maintainer:** gitdamnit (Evan Zellner)

## Purpose

Secret scanners inspect files on disk; they do not inspect what enters an AI
coding agent's model context. A credential can be clean in the repository and
still be transmitted to a cloud provider inside a prompt, a tool result, a
compaction transcript, or a generated title. strangerDanger operates at the
OpenCode V2 request boundaries and removes secrets from that outbound content
before transmission, while leaving the user's files untouched.

## Intended Users

Developers and teams running OpenCode against hosted model providers who need a
defense-in-depth control between their working tree and a third-party API. They
are comfortable adding a plugin to `opencode.jsonc` or installing a CLI, and they
expect a security tool to fail closed and to avoid corrupting their work.

## Functional Requirements

| ID | Requirement | Acceptance signal |
| --- | --- | --- |
| FR-1 | Detect secrets and PII in text with vendored gitleaks rules, clean-room rules, and entropy detectors | `sd scan` reports findings for known synthetic secrets |
| FR-2 | Redact outbound prompts, tool results, and the assembled agent-loop request before transmission | With the plugin loaded, a synthetic secret in a prompt/result is absent from the transmitted body |
| FR-3 | Cover transient `generate`, `title`, and `compaction` request kinds | Those hooks are registered and redact the same request shape |
| FR-4 | Pre-read inspection must never modify a file on disk | `tool.execute.before` contains no write call; only detection and audit occur |
| FR-5 | Fail closed on content that cannot be inspected | Oversize/timeout/error/cycle/over-depth yields an explicit `[REDACTED:...]` marker, not the original |
| FR-6 | Cover large output with windowed scanning | A secret straddling a window boundary is still detected |
| FR-7 | Keep audit records secret-free and project-scoped | Audit lines contain rule id/description/fingerprint/source/path/session id only |
| FR-8 | Support a project allowlist by fingerprint, ruleId, path, or regex | `sd allowlist` and `sd_allowlist_add` accept/reject entries accordingly |
| FR-9 | Provide a standalone CLI (`sd scan`, `sd redact`, `sd audit`, `sd rules`, `sd allowlist`, `sd version`) | `verify:package` exercises the installed `sd` binary |
| FR-10 | Register the plugin tools `sd_status`, `sd_audit`, `sd_allowlist_add`, `sd_allowlist_show`, `sd_scan` | Tools appear in the OpenCode runtime and in `runtime-*.json` |
| FR-11 | Operate with no dependency on a companion plugin | No cross-plugin imports; peer dependency is `@opencode/plugin` only |
| FR-12 | Hook callbacks never throw into the runtime | Every hook is wrapped; malformed events are tolerated |

## Nonfunctional Requirements

| ID | Requirement | Target |
| --- | --- | --- |
| NFR-1 | No raw secret is emitted by CLI, tools, or audit log | Verified by tests and `verify:package` (JSON must not contain the secret) |
| NFR-2 | Scanning large content is bounded | 256 MiB hard ceiling; 1 MiB windows with 64 KiB overlap; 2.5 s per-window budget |
| NFR-3 | Fast on large inputs | Whole-content keyword prefilter; no regex run when no keyword is present |
| NFR-4 | Filesystem hygiene | Audit files `0600`, directories `0700`, rotation to `.1`/`.2`/`.3` |
| NFR-5 | Portability | Node `>= 20` (CI on Node 22); OpenCode V2 with `@opencode/plugin >= 2.0.0` |
| NFR-6 | Maintainability | Detection engine decoupled from OpenCode; `src/engine` shared by plugin and CLI |
| NFR-7 | Reliability under failure | A hook error never breaks the runtime or a companion plugin |

## Scope and Exclusions

In scope for 0.2.0: the OpenCode V2 plugin, the `sd` CLI, the detection engine,
the audit log, the allowlist, packaging, CI, and the independence guarantees.

Out of scope (documented): provider-native WebSocket traffic, raw `http.request`
body rewriting, non-plain objects (`Map`/`Set`/`Date`/typed arrays), secrets that
match no rule after obfuscation, and any claim of universal leak prevention.

## Technical Constraints

- TypeScript, ESM, Node `>= 20`.
- OpenCode V2 plugin model: `Plugin.define({ id, setup })`; hooks registered via
  `ctx.tool.hook` / `ctx.session.hook` / `ctx.event.subscribe`; tools via
  `ctx.tool.transform` with JSON Schema.
- No runtime dependency other than the `@opencode/plugin` peer.
- Git That Shit, Checkpoint Orchestrator, and CheapCode are explicitly not
  dependencies and must not be touched by this project.

## Acceptance Criteria

1. `npm run typecheck`, `npm run lint`, `npm run build` succeed.
2. Unit, integration, security, and the full test suite pass.
3. `npm run verify:package` passes: the packed artifact installs, the `sd` binary
   runs, scans a synthetic secret without leaking it, and the plugin's default
   export has the V2 shape.
4. The Docker Plugin Test Lab reports 145/145 with strangerDanger at the verified
   commit.
5. README, CHANGELOG, LICENSE, and SECURITY accurately describe install,
   compatibility, limitations, and the threat model.

## Release Objectives

Ship v0.2.0 (security hardening + OpenCode V2 migration) as a GitHub release from
the verified commit, with the package ready for npm publication on request. The
release must not overstate coverage: it protects the documented OpenCode V2
request boundaries and fails closed elsewhere, and says so explicitly.
