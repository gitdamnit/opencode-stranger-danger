import type { Finding } from "../engine/types.js";
/** Rule count across every rule family. */
export declare function ruleCount(): number;
export type ToolDeps = {
    /** Project-scoped audit path for this plugin instance. */
    auditPath?: string;
};
/** `sd_status` */
export declare function sdStatus(deps?: ToolDeps): string;
/** `sd_audit` */
export declare function sdAudit(deps?: ToolDeps): string;
/** `sd_allowlist_show` */
export declare function sdAllowlistShow(): string;
/** `sd_allowlist_add` */
export declare function sdAllowlistAdd(args: {
    description?: string;
    fingerprint?: string;
    ruleId?: string;
    path?: string;
    regex?: string;
}): string;
/** Upper bound on content accepted by `sd_scan`. Keeps a model-invoked scan bounded. */
export declare const MAX_SD_SCAN_CHARS: number;
/**
 * `sd_scan` — returns secret-free metadata only.
 *
 * The input is bounded and scanned with the same chunk-safe path as the hooks,
 * so a very large `content` argument cannot exhaust memory or hang the server.
 */
export declare function sdScan(args: {
    content: string;
    source?: Finding["source"];
}): string;
//# sourceMappingURL=tools.d.ts.map