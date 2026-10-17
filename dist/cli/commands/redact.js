import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeSync, } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";
import { scanAndRedactBounded } from "../../engine/scanner.js";
import { writeAuditBatch, auditEntryFromFinding } from "../../engine/audit.js";
const BACKUP_DIR_MODE = 0o700;
const BACKUP_FILE_MODE = 0o600;
function isBinary(content) {
    for (let i = 0; i < Math.min(content.length, 8192); i++) {
        if (content[i] === 0)
            return true;
    }
    return false;
}
/**
 * Write `data` to `path` atomically with an explicit mode: write a sibling
 * temp file, fsync it, then rename over the destination. A crash leaves either
 * the old file or the new file, never a truncated mix.
 */
function atomicWrite(path, data, mode) {
    const dir = dirname(path);
    const tmp = join(dir, `.${basename(path)}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
    const fd = openSync(tmp, "w", mode);
    try {
        const buf = Buffer.from(data, "utf8");
        writeSync(fd, buf, 0, buf.length, 0);
        fsyncSync(fd);
    }
    finally {
        closeSync(fd);
    }
    renameSync(tmp, path);
}
/** Default backup location: a private per-user state directory, never the working tree. */
function defaultBackupDir() {
    const stateHome = process.env.XDG_STATE_HOME && process.env.XDG_STATE_HOME.length > 0
        ? process.env.XDG_STATE_HOME
        : join(homedir(), ".local", "state");
    return join(stateHome, "strangerdanger", "backups");
}
/** Create a backup that never collides with (and never deletes) an existing file. */
function writeSecureBackup(originalPath, content, dir) {
    mkdirSync(dir, { recursive: true, mode: BACKUP_DIR_MODE });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    let target = join(dir, `${basename(originalPath)}.${stamp}.bak`);
    let counter = 1;
    while (existsSync(target)) {
        target = join(dir, `${basename(originalPath)}.${stamp}.${counter}.bak`);
        counter++;
    }
    const fd = openSync(target, "w", BACKUP_FILE_MODE);
    try {
        writeSync(fd, content, 0, content.length, 0);
        fsyncSync(fd);
    }
    finally {
        closeSync(fd);
    }
    return target;
}
export async function cmdRedact(positional, flags = {}) {
    if (positional.length === 0) {
        console.error("Usage: sd redact <file>");
        process.exit(1);
    }
    const filePath = positional[0];
    const wantBackup = !!flags.backup || typeof flags["backup-dir"] === "string";
    if (!existsSync(filePath)) {
        console.error(`Error: File not found: ${filePath}`);
        process.exit(1);
    }
    let stats;
    try {
        stats = lstatSync(filePath);
    }
    catch (err) {
        console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
    }
    if (!stats.isFile()) {
        console.error(`Error: Refusing to redact non-regular file: ${filePath}`);
        process.exit(1);
    }
    try {
        const raw = readFileSync(filePath);
        if (isBinary(raw)) {
            console.error(`Error: Refusing to redact binary file: ${filePath}`);
            process.exit(1);
        }
        const content = raw.toString("utf8");
        const { redacted, findings, complete, policy } = scanAndRedactBounded(content, "file", filePath);
        if (findings.length === 0) {
            console.log("No secrets found. File unchanged.");
            return;
        }
        // A backup is explicit and lives outside the working tree by default,
        // so a plaintext copy of the secret is never dropped next to the file.
        let backupPath;
        if (wantBackup) {
            const dir = typeof flags["backup-dir"] === "string"
                ? resolve(flags["backup-dir"])
                : defaultBackupDir();
            backupPath = writeSecureBackup(filePath, raw, dir);
        }
        const mode = statSync(filePath).mode & 0o777;
        atomicWrite(filePath, redacted, mode);
        const auditEntries = findings.map((f) => auditEntryFromFinding(f, { filePath }));
        writeAuditBatch(auditEntries);
        console.log(`Redacted ${findings.length} secret(s) in ${filePath}`);
        if (backupPath) {
            console.log(`Backup saved to ${backupPath} (mode 0600)`);
        }
        else {
            console.log("No plaintext backup written (use --backup to keep one).");
        }
        if (!complete) {
            console.error(`Warning: content could not be fully inspected (${policy}); output was failed closed.`);
        }
        for (const f of findings) {
            console.log(`  ${f.ruleId}: ${f.redacted}`);
        }
    }
    catch (err) {
        console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
    }
}
//# sourceMappingURL=redact.js.map