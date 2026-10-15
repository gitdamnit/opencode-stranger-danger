import { loadAllowlist, saveAllowlistEntry } from "../../engine/allowlist.js";
import type { AllowlistEntry } from "../../engine/types.js";

function pickEntry(flags: Record<string, string | boolean>): AllowlistEntry {
    const entry: AllowlistEntry = {};
    const str = (v: string | boolean | undefined): string | undefined =>
        typeof v === "string" && v.length > 0 ? v : undefined;

    const description = str(flags.description);
    const fingerprint = str(flags.fingerprint);
    const ruleId = str(flags.ruleId) ?? str(flags["rule-id"]);
    const path = str(flags.path);
    const regex = str(flags.regex);

    if (description) entry.description = description;
    if (fingerprint) entry.fingerprint = fingerprint;
    if (ruleId) entry.ruleId = ruleId;
    if (path) entry.path = path;
    if (regex) entry.regex = regex;
    return entry;
}

export async function cmdAllowlist(
    subcommand: string,
    _positional: string[],
    flags: Record<string, string | boolean> = {},
): Promise<void> {
    if (subcommand === "show") {
        const allowlist = loadAllowlist();
        if (allowlist.entries.length === 0) {
            console.log("No allowlist entries.");
            return;
        }
        for (let i = 0; i < allowlist.entries.length; i++) {
            const e = allowlist.entries[i];
            console.log(`${i + 1}. ${e.description || "(no description)"}`);
            console.log(`   fingerprint: ${e.fingerprint || "—"}`);
            console.log(`   ruleId: ${e.ruleId || "—"}`);
            console.log(`   path: ${e.path || "—"}`);
            console.log(`   regex: ${e.regex || "—"}`);
        }
        return;
    }

    if (subcommand === "add") {
        const entry = pickEntry(flags);
        if (Object.keys(entry).length === 0 || (!entry.fingerprint && !entry.ruleId && !entry.path && !entry.regex)) {
            console.error("Usage: sd allowlist add --fingerprint <fp> | --ruleId <id> | --path <glob> | --regex <pattern> [--description \"...\"]");
            process.exit(1);
        }

        if (entry.regex) {
            try {
                new RegExp(entry.regex);
            } catch (err) {
                console.error(`Error: invalid --regex pattern: ${err instanceof Error ? err.message : String(err)}`);
                process.exit(1);
            }
        }
        if (entry.fingerprint && !/^[a-f0-9]{8}$/i.test(entry.fingerprint)) {
            console.error("Error: --fingerprint must be 8 hexadecimal characters.");
            process.exit(1);
        }

        saveAllowlistEntry(entry);
        console.log("Allowlist entry added.");
        return;
    }

    console.log("Usage: sd allowlist <show|add> [options]");
}
