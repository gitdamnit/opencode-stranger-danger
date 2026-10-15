#!/usr/bin/env node

import { parseArgs, USAGE } from "./args.js";
import { cmdScan } from "./commands/scan.js";
import { cmdRedact } from "./commands/redact.js";
import { cmdAudit } from "./commands/audit.js";
import { cmdRules } from "./commands/rules.js";
import { cmdAllowlist } from "./commands/allowlist.js";
import { VERSION } from "../shared/version.js";

async function main(): Promise<void> {
    const { command, positional, flags } = parseArgs(process.argv);

    if (flags.help || command === "help") {
        console.log(USAGE);
        return;
    }

    switch (command) {
        case "scan":
            await cmdScan(positional, flags);
            break;
        case "redact":
            await cmdRedact(positional, flags);
            break;
        case "audit":
            await cmdAudit();
            break;
        case "rules":
            await cmdRules();
            break;
        case "allowlist":
            await cmdAllowlist(positional[0] || "show", positional.slice(1), flags);
            break;
        case "version":
            console.log(`strangerDanger v${VERSION}`);
            break;
        default:
            console.error(`Unknown command: ${command}`);
            console.log(USAGE);
            process.exit(1);
    }
}

main().catch((err) => {
    console.error(`Fatal error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
});
