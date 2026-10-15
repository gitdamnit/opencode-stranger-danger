export type Rule = {
    id: string;
    description: string;
    regex: RegExp;
    keywords: string[];
    entropy?: number;
};

export type Finding = {
     ruleId: string;
     description: string;
     match: string;
     redacted: string;
     offset: number;
     source: "file" | "context" | "output" | "message";
     filePath?: string;
 };

export type AuditEntry = {
    timestamp: string;
    sessionId?: string;
    source: string;
    ruleId: string;
    description: string;
    fingerprint: string;
    filePath?: string;
};

export type AllowlistEntry = {
    description?: string;
    fingerprint?: string;
    ruleId?: string;
    path?: string;
    regex?: string;
};

export type Allowlist = {
    entries: AllowlistEntry[];
};
