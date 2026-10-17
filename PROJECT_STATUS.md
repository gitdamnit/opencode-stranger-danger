# Project Status

## Current Phase

In Progress

## Repository State

<!-- Machine-maintained by `prodoc update`. Do not hand-edit. -->
<!-- prodoc:observed:start -->
<!-- Observed from Git metadata only, by `prodoc update`. This block is not evidence that the implementation or its tests are correct; record that under `## Verification Evidence`. -->
- **Observed branch:** feat/stranger-danger-v2-hardening
- **Observed commit:** 9cfd8135429bffb2e5e32e97f23bec3f5b6277bd
- **Observed working tree:** dirty
- **Observed at:** 2026-10-17T00:24:21Z
<!-- prodoc:observed:end -->

## Verification Evidence

- **Verification:** commit `9cfd8135429bffb2e5e32e97f23bec3f5b6277bd` — local full suite green (322 tests, 0 fail) after a clean `npm ci`, with a rebuild producing byte-identical `dist/` — evidence `/tmp/opencode/sd-verify.log` (typecheck, lint, build, unit, integration, security, package validation all `rc=0`)
- **Verification:** commit `9cfd8135429bffb2e5e32e97f23bec3f5b6277bd` — `npm run verify:package` passed every artifact check (pack, isolated install, `sd version`/`sd rules`, secret-free scan JSON, engine export, V2 plugin shape, root `index.js`) — evidence `/tmp/opencode/sd-verify.log`
- **Verification:** commit `9cfd8135429bffb2e5e32e97f23bec3f5b6277bd` — Docker Plugin Test Lab, `stranger-danger` 0.2.0, image `opencode-plugin-lab:local` (`sha256:76ebd805cd548a638b9b1508e5f16e680cd5b082cd3f3561d28f2f2301336ff1`), 145/145 passed on OpenCode 2.0.21 / Node 22.23.3 — evidence `/home/evan/Projects/opencode-plugin-lab/reports/rc-evidence.json` and `/home/evan/Projects/opencode-plugin-lab/reports/test-report.md`

## Completed Work

- [Implemented] OpenCode V2 migration — `Plugin.define({ id: "gitdamnit.stranger-danger", setup })`, five JSON-Schema tools, `session.*` hooks — `src/plugin/index.ts`
- [Implemented] Read-only pre-read inspection (no disk writes) — `src/plugin/layer1.ts`
- [Implemented] Bounded, windowed, fail-closed scanner — `src/engine/scanner.ts`
- [Implemented] Project-scoped, secret-free audit log with rotation — `src/engine/audit.ts`
- [Implemented] Allowlist by fingerprint/ruleId/path/regex — `src/engine/allowlist.ts`
- [Implemented] Atomic `sd redact` with opt-in out-of-tree backup — `src/cli/commands/redact.ts`
- [Tested] Unit, integration, security and full suites green at `9cfd813542` — `/tmp/opencode/sd-verify.log`
- [Tested] Packed-artifact validation green at `9cfd813542` — `/tmp/opencode/sd-verify.log`
- [Implemented] CI (typecheck, lint, build, tests, package validation) and npm publish workflow — `.github/workflows/ci.yml`, `.github/workflows/publish.yml`
- [Implemented] MIT `LICENSE` and vulnerability-disclosure `SECURITY.md` — `LICENSE`, `SECURITY.md`
- [Planned] npm publication of `@gitdamnit/stranger-danger` (requires registry credentials)

## Tests

| Suite | Command | Result | Evidence |
| --- | --- | --- | --- |
| typecheck | `npm run typecheck` | Pass | `/tmp/opencode/sd-verify.log` |
| lint | `npm run lint` | Pass | `/tmp/opencode/sd-verify.log` |
| build | `npm run build` | Pass (no `dist/` drift) | `/tmp/opencode/sd-verify.log` |
| unit | `npm run test:unit` | Pass | `/tmp/opencode/sd-verify.log` |
| integration | `npm run test:integration` | Pass | `/tmp/opencode/sd-verify.log` |
| security | `npm run test:security` | Pass | `/tmp/opencode/sd-verify.log` |
| full | `npm test` | Pass (322) | `/tmp/opencode/sd-verify.log` |
| package | `npm run verify:package` | Pass | `/tmp/opencode/sd-verify.log` |
| runtime lab | Docker Plugin Test Lab `--all --tier validate` | Pass (145) | `/home/evan/Projects/opencode-plugin-lab/reports/test-report.json` |

## Known Defects

- None known. Non-blocking observations: `tests/debug.test.ts` and `tests/debug2.test.ts` are trivial sanity stubs; the provider-WebSocket, raw-HTTP-body, exotic-object, and encoded-secret gaps are documented limitations, not defects.

## Blockers

- npm publication is blocked on registry ownership/authentication: the `@gitdamnit` scope is not published and no `NPM_TOKEN` secret is configured. GitHub publication is unaffected.

## Next Actions

1. Merge the release pull request for `feat/stranger-danger-v2-hardening` into `master`.
2. Create the `v0.2.0` annotated tag and the GitHub release.
3. When credentials exist, publish `@gitdamnit/stranger-danger@0.2.0` to npm and verify a clean install.

## Release Status

Release candidate 0.2.0 is frozen at commit `9cfd8135429bffb2e5e32e97f23bec3f5b6277bd`
on branch `feat/stranger-danger-v2-hardening`. Version `0.2.0` in `package.json` and
`src/shared/version.ts`. Validated on OpenCode `2.0.21` / Node `22.23.3` in Docker
image `opencode-plugin-lab:local`
(`sha256:76ebd805cd548a638b9b1508e5f16e680cd5b082cd3f3561d28f2f2301336ff1`),
145/145 lab tests and 322/322 local tests green. GitHub publication is the
remaining step; npm publication is deferred pending credentials.
