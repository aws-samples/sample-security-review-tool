export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Remediation {
    readonly id: string;
    readonly priority: Severity;
    readonly description?: string;
    readonly remediation: string;
}
