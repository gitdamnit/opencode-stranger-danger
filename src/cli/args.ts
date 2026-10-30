import { VERSION } from "../shared/version.js";

export interface CliArgs {
    command: string;
    positional: string[];
    flags: Record<string, string | boolean>;
}

export function parseArgs(argv: string[]): CliArgs {
     const args = argv.slice(2);
     let command = args[0] || "help";
     const positional: string[] = [];
     const flags: Record<string, string | boolean> = {};

     // --help is always a flag, never a command
     if (command === "--help" || command === "-h") {
         flags.help = true;
         command = "help";
     }

     for (let i = 1; i < args.length; i++) {
         const arg = args[i];
         if (arg.startsWith("--")) {
             const eq = arg.indexOf("=");
             if (eq !== -1) {
                 // --flag=value
                 flags[arg.slice(2, eq)] = arg.slice(eq + 1);
                 continue;
             }
             const key = arg.slice(2);
             const next = args[i + 1];
             if (next && !next.startsWith("--")) {
                 flags[key] = next;
                 i++;
             } else {
                 flags[key] = true;
             }
         } else if (arg.startsWith("-") && arg.length === 2) {
             const key = arg[1];
             // Short flag aliases
             if (key === "j") {
                 flags["json"] = true;
             } else if (key === "h") {
                 flags["help"] = true;
             } else {
                 const next = args[i + 1];
                 if (next && !next.startsWith("-")) {
                     flags[key] = next;
                     i++;
                 } else {
                     flags[key] = true;
                 }
             }
         } else if (arg.startsWith("-") && arg.length > 2) {
             // Short flags grouped (e.g., -jh)
             const chunk = arg.slice(1);
             for (const ch of chunk) {
                 if (ch === "j") {
                     flags["json"] = true;
                 } else if (ch === "h") {
                     flags["help"] = true;
                 } else {
                     flags[ch] = true;
                 }
             }
         } else {
             positional.push(arg);
         }
     }

     return { command, positional, flags };
 }

export const USAGE = `
strangerDanger v${VERSION} — Secret and PII redaction guard

Usage: sd <command> [options]

Commands:
  scan <file|directory|->    Scan a file, directory, or stdin for secrets
  redact <file>              Redact secrets in a file in-place (atomic, no plaintext backup by default)
  audit                      Show the audit log
  rules                      List all active detection rules
  allowlist add              Add an allowlist entry
  allowlist show             Show current allowlist entries
  version                    Show version

Options:
  --source <type>            Source type for scan: file, context, output, message
  --json                     Output in JSON format (never contains raw secrets)
  --backup                   Redact with a permission-restricted backup outside the working tree
  --backup-dir <dir>         Store the redaction backup in <dir> instead of the default location
  --help                     Show this help message
`;
