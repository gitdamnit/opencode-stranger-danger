export interface CliArgs {
    command: string;
    positional: string[];
    flags: Record<string, string | boolean>;
}
export declare function parseArgs(argv: string[]): CliArgs;
export declare const USAGE = "\nstrangerDanger v0.2.2 \u2014 Secret and PII redaction guard\n\nUsage: sd <command> [options]\n\nCommands:\n  scan <file|directory|->    Scan a file, directory, or stdin for secrets\n  redact <file>              Redact secrets in a file in-place (atomic, no plaintext backup by default)\n  audit                      Show the audit log\n  rules                      List all active detection rules\n  allowlist add              Add an allowlist entry\n  allowlist show             Show current allowlist entries\n  version                    Show version\n\nOptions:\n  --source <type>            Source type for scan: file, context, output, message\n  --json                     Output in JSON format (never contains raw secrets)\n  --backup                   Redact with a permission-restricted backup outside the working tree\n  --backup-dir <dir>         Store the redaction backup in <dir> instead of the default location\n  --help                     Show this help message\n";
//# sourceMappingURL=args.d.ts.map