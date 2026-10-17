# Decision Log

## How to Use This Log

1. Copy the block below to the end of the `## Decisions` section.
2. Use the next free four-digit ID. IDs are never reused and never renumbered.
3. Date the record the day the decision was actually made (`YYYY-MM-DD`).
4. Record the alternatives you rejected and why.
5. Never rewrite history. If a decision changes, append a superseding record.

```markdown
### D-0001 — Short imperative title

- **Date:** YYYY-MM-DD
- **Status:** Accepted
- **Context:** the situation and the constraint that forced a choice
- **Alternatives Considered:** option A (rejected because ...), option B (rejected because ...)
- **Decision:** what was decided, in one or two sentences
- **Rationale:** why this option wins, including what it costs
- **Consequences:** what follows from it — new constraints, follow-up work, risks
- **Supersedes:** None
```

Allowed statuses: `Proposed`, `Accepted`, `Superseded`, `Deprecated`, `Rejected`.

## Decisions

### D-0001 — Enforce redaction at the OpenCode V2 session.* request hooks

- **Date:** 2026-05-13
- **Status:** Accepted
- **Context:** 0.1.0 scanned files and audited after the fact from the V1 `event`
  handler. That cannot prevent disclosure: the event stream is observational and
  arrives after a request has been admitted.
- **Alternatives Considered:** keep the V1 `event` handler (rejected: post-hoc,
  cannot stop transmission); rewrite `http.request` bodies (rejected: not a
  supported stable surface and it breaks provider request shaping); patch files
  on read (rejected: corrupts the user's working tree).
- **Decision:** Register all four V2 model-request hooks (`session.prompt`,
  `session.context`, `session.generate`, `session.title`), plus
  `session.compaction` and `tool.execute.after`, and redact the assembled
  request immediately before dispatch.
- **Rationale:** These are the supported boundaries that run before
  transmission, and registering all of them makes redaction independent of the
  order in which other plugins run.
- **Consequences:** Enforcement depends on OpenCode V2 exposing these hooks;
  surfaces outside `system`/`messages` (raw HTTP bodies, provider WebSockets) are
  out of scope and documented as such.
- **Supersedes:** None

### D-0002 — The pre-read hook is strictly read-only

- **Date:** 2026-05-13
- **Status:** Accepted
- **Context:** The V1 pre-read hook rewrote source files on disk when it detected
  a secret, silently modifying the user's working tree.
- **Alternatives Considered:** keep rewriting files (rejected: data loss and
  corruption, unacceptable for an inspection hook); delete the file (rejected:
  far worse); warn only (rejected: does not protect the model context).
- **Decision:** `tool.execute.before` detects and audits only; it never writes.
  Redaction happens at the result/request boundaries instead.
- **Rationale:** An inspection hook must not have side effects. The result and
  request boundaries already cover what the model sees.
- **Consequences:** The on-disk file still contains the secret; users rely on
  `sd redact` or their own tooling to remediate the file. This is stated in the
  README.
- **Supersedes:** None

### D-0003 — Fail closed on content that cannot be inspected

- **Date:** 2026-05-16
- **Status:** Accepted
- **Context:** A cyclic tool output overflowed the stack; the hook swallowed the
  error and the entire result — including plain string secrets — passed through
  unredacted. Truncating large output had the same fail-open shape.
- **Alternatives Considered:** fail open (rejected: leaks silently); truncate at
  a size limit (rejected: a secret past the limit leaks); throw from the hook
  (rejected: would break the runtime and companion plugins).
- **Decision:** Bounded, windowed scanning with explicit fail-closed markers.
  Oversize, window timeout/error, cycles, and nesting beyond 32 levels all
  replace the uninspectable content with a `[REDACTED:...]` marker.
- **Rationale:** Losing content is recoverable; leaking a credential is not.
- **Consequences:** Very large or exotic payloads lose content and gain a marker.
  The marker is documented and visible to the user and the model.
- **Supersedes:** None

### D-0004 — Audit records store metadata and an 8-hex fingerprint, never the secret

- **Date:** 2026-05-16
- **Status:** Accepted
- **Context:** An audit log that contains the matched value is itself a secret
  store, and it is easy to attach to a bug report by accident.
- **Alternatives Considered:** store the raw match (rejected: creates a new
  credential store); store nothing (rejected: no operator visibility); store a
  full SHA-256 (rejected: unnecessary precision, still correlatable).
- **Decision:** Record rule id, description, source, file path, optional session
  id, and an 8-hex fingerprint of the match. Never the match or the redaction
  token body.
- **Rationale:** Operators can triage and allowlist by fingerprint without a log
  that is dangerous to share.
- **Consequences:** The log is metadata-only; `0600` files in a `0700` directory,
  with size-bounded rotation that preserves records.
- **Supersedes:** None

### D-0005 — Remain independent of companion OpenCode plugins

- **Date:** 2026-05-16
- **Status:** Accepted
- **Context:** strangerDanger is developed alongside Git That Shit and Checkpoint
  Orchestrator in a shared test lab, which invites accidental coupling.
- **Alternatives Considered:** integrate directly with the companions (rejected:
  couples release cycles and creates load-order dependencies); share a database
  or config namespace (rejected: cross-contamination and mixed audit records).
- **Decision:** No cross-plugin imports, no shared state, no required load order.
  The only interop surface is the optional, read-only, semver-versioned
  `@gitdamnit/stranger-danger/engine` export.
- **Rationale:** A security plugin that can be broken by, or break, an unrelated
  plugin is not trustworthy, and ordering-independent redaction (D-0001) makes
  coupling unnecessary.
- **Consequences:** The companions are never required; failure isolation is
  mandatory in every hook; the independence test suite guards this.
- **Supersedes:** None

### D-0006 — Release v0.2.0 on GitHub; treat npm publication as a separate, manual step

- **Date:** 2026-10-16
- **Status:** Accepted
- **Context:** The repository contains `.github/workflows/publish.yml`, which
  publishes to npm on any `v*.*.*` tag push using the `NPM_TOKEN` secret. No such
  secret (or repository variable) is configured, and the package is not yet
  present on the npm registry.
- **Alternatives Considered:** publish to npm as part of this release (rejected:
  registry ownership/authentication is not established and publication is
  explicitly out of scope for this session); delete or disable `publish.yml`
  (rejected: it is the intended release path once credentials exist).
- **Decision:** Create the `v0.2.0` annotated tag and GitHub release at the
  verified commit. Do not publish to npm. Record the exact npm publication
  checklist for a later, explicitly authorized run.
- **Rationale:** GitHub publication is fully authorized and verifiable now; npm
  publication requires credentials and registry setup that do not exist.
- **Consequences:** Pushing the tag triggers `publish.yml`, which will fail at
  the npm step because `NPM_TOKEN` is unset. This is expected and does not affect
  the GitHub release. npm distribution must not be reported as complete.
- **Supersedes:** None
