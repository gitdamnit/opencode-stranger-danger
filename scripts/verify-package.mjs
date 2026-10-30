#!/usr/bin/env node
/**
 * Package validation: build, pack the npm tarball, install it into an isolated
 * temporary project, and exercise the installed artifact (standalone CLI plus
 * the plugin's default export). This proves the published `files`, `exports`,
 * `bin`, and runtime dependencies are correct — not just the source tree.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, readdirSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const run = (cmd, args, opts = {}) =>
    execFileSync(cmd, args, { stdio: "pipe", encoding: "utf8", ...opts });

// Derive the identity from package.json so the validation can never drift from
// the name that is actually published.
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const pkgName = pkg.name;
const pkgPath = pkgName.split("/");
const tarballPrefix = pkgName.replace(/^@/, "").replace(/\//g, "-") + "-";

function step(label, fn) {
    process.stdout.write(`- ${label} ... `);
    const result = fn();
    process.stdout.write("ok\n");
    return result;
}

let workdir;
try {
    step("build", () => run("npm", ["run", "build"], { cwd: root, stdio: "inherit" }));

    const packOutput = step("npm pack", () => run("npm", ["pack", "--json"], { cwd: root }));
    const tarballName = JSON.parse(packOutput)[0].filename;
    const tarballPath = join(root, tarballName);

    workdir = mkdtempSync(join(tmpdir(), "sd-package-"));
    step("init isolated project", () =>
        run("npm", ["init", "-y"], { cwd: workdir, stdio: "ignore" }));
    step("install packed tarball", () =>
        run("npm", ["install", tarballPath, "--no-audit", "--no-fund"], { cwd: workdir, stdio: "ignore" }));

    const bin = join(workdir, "node_modules", ".bin", process.platform === "win32" ? "sd.cmd" : "sd");
    if (!existsSync(bin)) throw new Error("installed package did not provide the `sd` bin");

    const version = step("run `sd version`", () => run(bin, ["version"], { cwd: workdir })).trim();
    if (!/v\d+\.\d+\.\d+/.test(version)) throw new Error(`unexpected version output: ${version}`);
    // The runtime VERSION constant is maintained separately from package.json, so
    // assert they agree; a mismatch means the shipped CLI misreports its release.
    if (!version.includes(`v${pkg.version}`)) {
        throw new Error(`sd version reported ${JSON.stringify(version)} but package.json is ${pkg.version}`);
    }

    step("run `sd rules`", () => {
        const out = run(bin, ["rules"], { cwd: workdir });
        if (!/Total rules: \d+/.test(out)) throw new Error("sd rules did not report a rule count");
    });

    step("scan detects a synthetic secret without leaking it", () => {
        // High-entropy synthetic token so the github-pat rule's entropy gate accepts it.
        const secret = "ghp_" + "aB3xK9mQ2pR7vL4nJ8wC5tY1cF6hA0sD8gE2";
        const out = run(bin, ["scan", "-", "--json"], {
            cwd: workdir,
            input: `const k = "${secret}";`,
        });
        const parsed = JSON.parse(out);
        if (!Array.isArray(parsed.findings) || parsed.findings.length === 0) {
            throw new Error("scan JSON reported no findings");
        }
        if (out.includes(secret)) throw new Error("scan JSON leaked the raw secret");
    });

    step("standalone engine export resolves", () => {
        run(process.execPath, ["--input-type=module", "-e",
            `import(${JSON.stringify(`${pkgName}/engine`)}).then(m=>{if(typeof m.scan!=='function')process.exit(1)})`,
        ], { cwd: workdir });
    });

    step("plugin default export has the V2 shape", () => {
        run(process.execPath, ["--input-type=module", "-e",
            `import(${JSON.stringify(pkgName)}).then(m=>{const p=m.default;if(!p||p.id!=='gitdamnit.stranger-danger'||typeof p.setup!=='function')process.exit(1)})`,
        ], { cwd: workdir });
    });

    // OpenCode resolves a plugin *directory* to <dir>/index.{ts,js} and ignores
    // main/exports, so the shipped package must include a root entrypoint.
    step("published package includes the root directory entrypoint", () => {
        const entry = join(workdir, "node_modules", ...pkgPath, "index.js");
        if (!existsSync(entry)) throw new Error("package is missing root index.js (directory installs would not load)");
        const src = readFileSync(entry, "utf8");
        if (!/export\s*\{\s*default\s*\}/.test(src)) throw new Error("root index.js does not export a default plugin");
    });

    // Clean up the tarball produced by pack.
    try { rmSync(tarballPath, { force: true }); } catch { /* ignore */ }

    console.log("\nPackage verification passed.");
} catch (err) {
    console.error("\nPackage verification FAILED:", err instanceof Error ? err.stack ?? err.message : err);
    process.exitCode = 1;
} finally {
    if (workdir) {
        try { rmSync(workdir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
    // Remove any stray tarballs in the repo root.
    try {
        for (const f of readdirSync(root)) {
            if (f.startsWith(tarballPrefix) && f.endsWith(".tgz")) {
                rmSync(join(root, f), { force: true });
            }
        }
    } catch { /* ignore */ }
}
