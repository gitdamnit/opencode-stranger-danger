# Security Policy

strangerDanger is a secret- and PII-redaction guard for AI coding agents. It
sits at the OpenCode V2 request boundaries and tries to keep secrets out of the
model's context window. It is a defense-in-depth layer, **not** a guarantee that
no secret can ever reach a provider. The exact surfaces it protects, and the
blind spots it does not, are listed below and in the README.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x | Yes |
| 0.1.x | No — superseded by the V2 rewrite; upgrade to 0.2.x |

Compatibility: OpenCode V2 runtime, `@opencode/plugin >= 2.0.0`
(validated against `@opencode/plugin@2.0.29` on OpenCode `2.0.21`).

## Reporting a vulnerability

Please report suspected vulnerabilities privately, not in a public issue:

- Open a **private security advisory** at
  https://github.com/gitdamnit/opencode-stranger-danger/security/advisories/new
- Or email the maintainer listed on the repository profile.

Please include: affected version, OpenCode/Node versions, a description of the
issue, and a minimal reproduction if you have one. If a real secret is involved,
rotate it first — do **not** paste live credentials into a report. Use synthetic
values with the same shape.

We aim to acknowledge reports within 7 days and to publish a fix or an accurate
assessment as soon as practical. There is no bug-bounty program.

## What this plugin protects

- **Prompts, tool results, and assembled model requests** — the `session.prompt`,
  `session.context`, `session.generate`, `session.title`, and
  `session.compaction` hooks redact text (and string leaves of plain
  objects/arrays) immediately before transmission, plus `tool.execute.after` for
  tool output, error messages, and error metadata.
- **File inspection is read-only.** `tool.execute.before` detects and audits; it
  never rewrites a file on disk.
- **No raw secrets in output.** The CLI, the plugin tools, and the audit log
  report safe metadata (rule id, description, source, line/column, an 8-hex
  fingerprint, and the redaction token) — never the matched value.
- **Fail closed.** Content that cannot be inspected (over the size ceiling, a
  window timeout or error, a cyclic or over-deep structure) is replaced by an
  explicit `[REDACTED:...]` marker rather than passed through.

## Known limitations (by design)

- **Provider-native WebSocket traffic** is not covered. The experimental
  `experimental.ws.*` hooks are deliberately not registered. Plain-HTTP
  providers and the HTTP fallback of a WebSocket route are covered.
- **Raw HTTP bodies.** The plugin edits assembled `system`/`messages`, not
  `http.request` bodies. Content a provider layer adds outside those is not
  scanned. `event.subscribe` is observation-only (post-admission).
- **Structured values.** Only string leaves of plain objects/arrays are
  redacted. Exotic objects (`Map`, `Set`, `Date`, typed arrays) are passed
  through unchanged; nesting deeper than 32 levels, and cycles, fail closed.
- **Encoded secrets.** Detection is pattern- and entropy-based. Base64- or
  otherwise obfuscated secrets that match no rule are not detected by that rule.
- **Not a prevention guarantee.** A secret that no rule matches, or that is
  transmitted through a surface listed above, is not stopped. Treat this as one
  layer alongside `.gitignore`, secret managers, and provider-side controls.

## Recommended operational practice

- Treat the audit log (`<project>/.opencode/state/strangerdanger-audit.jsonl`)
  as sensitive operational metadata even though it never stores secret values.
  It is written `0600` inside a `0700` directory and is git-ignored.
- Rotate any credential the moment you suspect it was transmitted, regardless of
  what this plugin reported.

## License

MIT — see [LICENSE](LICENSE).
