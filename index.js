/**
 * Root plugin entrypoint.
 *
 * OpenCode resolves a plugin *directory* (for example `{ "package": "/path/to/plugin" }`
 * or `"./plugins/local"`) to `<directory>/index.{ts,js}` — it does not consult
 * `main` or `exports`. Without a root entrypoint, a directory-path configuration
 * silently fails to load the plugin ("Plugin entrypoint not found"), leaving the
 * user unprotected while their config claims otherwise.
 *
 * npm consumers resolve through `exports` (see package.json), so this file only
 * affects directory/path loading. Both paths expose the same default export.
 */
export { default } from "./dist/plugin/index.js";
