# Project Status

## Current Phase

Released

## Repository State

<!-- Machine-maintained by `prodoc update`. Do not hand-edit. -->
<!-- prodoc:observed:start -->
<!-- Observed from Git metadata only, by `prodoc update`. This block is not evidence that the implementation or its tests are correct; record that under `## Verification Evidence`. -->
- **Observed branch:** master
- **Observed commit:** 6f958dc5cf4f9c0700a8aaa0ea2ef42ad04c7e5e
- **Observed working tree:** dirty
- **Observed at:** 2026-10-30T01:48:47Z
<!-- prodoc:observed:end -->

## Verification Evidence

- **Verification:** commit `9cfd8135429bffb2e5e32e97f23bec3f5b6277bd` — local full suite green (322 tests, 0 fail) after a clean `npm ci`, with a rebuild producing byte-identical `dist/` — evidence `/tmp/opencode/sd-verify.log` (typecheck, lint, build, unit, integration, security, package validation all `rc=0`)
- **Verification:** commit `9cfd8135429bffb2e5e32e97f23bec3f5b6277bd` — `npm run verify:package` passed every artifact check (pack, isolated install, `sd version`/`sd rules`, secret-free scan JSON, engine export, V2 plugin shape, root `index.js`) — evidence `/tmp/opencode/sd-verify.log`
- **Verification:** commit `9cfd8135429bffb2e5e32e97f23bec3f5b6277bd` — Docker Plugin Test Lab, `stranger-danger` 0.2.0, image `opencode-plugin-lab:local` (`sha256:76ebd805cd548a638b9b1508e5f16e680cd5b082cd3f3561d28f2f2301336ff1`), 145/145 passed on OpenCode 2.0.21 / Node 22.23.3 — evidence `/home/evan/Projects/opencode-plugin-lab/reports/rc-evidence.json` and `/home/evan/Projects/opencode-plugin-lab/reports/test-report.md`
- **Verification:** commit `64929cbaf509dc1b21011d13997c06dad92d6189` — release commit is byte-identical to the verified source (`git diff 9cfd813542..64929cb -- src tests dist scripts rules .github` is empty); CI green — evidence https://github.com/gitdamnit/opencode-stranger-danger/actions/runs/38986326595
- **Verification:** commit `b634ce5cb84c533c1fd1f6802d922b6e812e5afb` — merge commit on `master`; `git diff 9cfd813542..b634ce5 -- src tests dist` empty; CI on `master` green; clean install from the public tag installed, ran `sd version` → 0.2.0, detected a synthetic `github-pat` with the raw value absent from output — evidence `/tmp/opencode/clean-install.log`
- **Verification:** commit `b634ce5cb84c533c1fd1f6802d922b6e812e5afb` (annotated tag `v0.2.0`) — GitHub release published; the tag-triggered `publish.yml` workflow passed every gate (typecheck, lint, unit, integration, security, build, package validation) and failed only at `npm publish` with `ENEEDAUTH` (no token), so nothing was published to npm — evidence https://github.com/gitdamnit/opencode-stranger-danger/releases/tag/v0.2.0

## Completed Work

- [Implemented] OpenCode V2 migration — `Plugin.define({ id: "gitdamnit.stranger-danger", setup })`, five JSON-Schema tools, `session.*` hooks — `src/plugin/index.ts`
- [Implemented] Read-only pre-read inspection (no disk writes) — `src/plugin/layer1.ts`
- [Implemented] Bounded, windowed, fail-closed scanner — `src/engine/scanner.ts`
- [Implemented] Project-scoped, secret-free audit log with rotation — `src/engine/audit.ts`
- [Implemented] Allowlist by fingerprint/ruleId/path/regex — `src/engine/allowlist.ts`
- [Implemented] Atomic `sd redact` with opt-in out-of-tree backup — `src/cli/commands/redact.ts`
- [Tested] Unit, integration, security and full suites green at `9cfd813542` — `/tmp/opencode/sd-verify.log`
- [Tested] Packed-artifact validation green at `9cfd813542` — `/tmp/opencode/sd-verify.log`
- [Implemented] CI and npm publish workflows — `.github/workflows/ci.yml`, `.github/workflows/publish.yml`
- [Implemented] MIT `LICENSE` and vulnerability-disclosure `SECURITY.md` — `LICENSE`, `SECURITY.md`
- [Published] GitHub release `v0.2.0` at merge commit `b634ce5cb84c533c1fd1f6802d922b6e812e5afb` — https://github.com/gitdamnit/opencode-stranger-danger/releases/tag/v0.2.0
- [Published] npm `@gitdamnit/opencode-stranger-danger@0.2.1` then `0.2.2` (version-reporting fix) through the manual OIDC workflow — https://www.npmjs.com/package/@gitdamnit/opencode-stranger-danger

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
| clean install | clone `v0.2.0` → `npm pack` → install into isolated project | Pass | `/tmp/opencode/clean-install.log` |
| release CI | `CI` on merge commit `b634ce5` | Pass | https://github.com/gitdamnit/opencode-stranger-danger/actions/runs/38986400189 |
| npm publish (tag) | `Publish to npm` on tag `v0.2.0` | Fail (expected: `ENEEDAUTH`) | https://github.com/gitdamnit/opencode-stranger-danger/actions/runs/38986473186 |
| npm publish (OIDC) | `Publish to npm` on tag `v0.2.2` | Pass (signed provenance) | https://github.com/gitdamnit/opencode-stranger-danger/actions/runs/40987247633 |
| registry clean install | `npm install @gitdamnit/opencode-stranger-danger@0.2.2` in an empty project | Pass (`sd version` → 0.2.2, 236 rules, plugin + engine exports) | https://www.npmjs.com/package/@gitdamnit/opencode-stranger-danger |
| OpenCode runtime load | `opencode run` with all three toolkit plugins configured | Pass (none failed to load) | OpenCode 2.2.1, local |

## Known Defects

- None known. Non-blocking observations: `tests/debug.test.ts` and `tests/debug2.test.ts` are trivial sanity stubs; the provider-WebSocket, raw-HTTP-body, exotic-object, and encoded-secret gaps are documented limitations, not defects.

## Blockers

- None. `0.2.2` is published to the public npm registry with signed provenance.

## Next Actions

1. None for this release. Future releases dispatch the manual `Publish to npm`
   workflow against their release tag.
2. The `v0.2.0` GitHub release remains GitHub-only by design; npm's 0.2 line
   starts at `0.2.1` because `v0.2.0` tags a commit whose `package.json` named a
   package that does not exist (see `D-0007`).

## Release Status

**v0.2.2 — RELEASED (GitHub + npm).** Annotated tag `v0.2.2` on `master`.
npm `latest` is `0.2.2`:
https://www.npmjs.com/package/@gitdamnit/opencode-stranger-danger

Publication ran through the manual OIDC workflow
(https://github.com/gitdamnit/opencode-stranger-danger/actions/runs/40987247633)
and signed a provenance statement. Verified by installing `0.2.2` from the
registry into an empty project: `sd version` reports `v0.2.2`, `sd rules` reports
236 rules, the default export is `gitdamnit.stranger-danger` with a `setup`
function, `./engine` exports `scan`, and the root `index.js` is present. All
three toolkit plugins were then loaded together in a real OpenCode `2.2.1`
runtime with no load failures.

`0.2.1` was published first and is immutable; it reported `0.2.0` because
`src/shared/version.ts` had not been bumped, which `0.2.2` fixes.
