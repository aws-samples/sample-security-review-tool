import type { ScanResult } from '../../../src/assess/scanning/types.js';


export class FixValidationResult {
    constructor(public readonly targetIssue: ScanResult, public readonly fixedOriginalFinding: boolean, public readonly introducedFindings: ReadonlyArray<ScanResult> = []) { }

    get isSuccessful(): boolean {
        return this.fixedOriginalFinding && !this.introducedRegressions;
    }

    get introducedRegressions(): boolean {
        return this.introducedFindings.length > 0;
    }

    get failureDescription(): string {
        if (!this.fixedOriginalFinding && this.introducedRegressions) return `The remediation instructions did NOT resolve the original finding and it also created new security issues.`;
        if (this.fixedOriginalFinding && this.introducedRegressions) return `The remediation instructions resolved the original finding, but created new security issues.`;
        return `The remediation instructions did NOT resolve the original finding.`;
    }
}
