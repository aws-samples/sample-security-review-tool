import * as fs from 'node:fs';
import * as path from 'node:path';
import { AssessCoordinator } from '../../../src/assess/coordinator.js';
import type { ScanResult } from '../../../src/assess/scanning/types.js';
import type { Scanner } from '../../shared/rule-catalog/src/index.js';

const ISSUES_FILE = path.join('.srt', 'issues.json');

export interface RescanResult {
    targetRuleStillFires: boolean;
    newRulesTriggered: string[];
    validationPassed: boolean;
    validationError?: string;
}

/**
 * Re-runs the scanner on a fixture after a fix has been applied and returns
 * objective pass signals: target rule cleared, no new rules triggered,
 * fixture still parses.
 */
export class RescanChecker {
    public async compare(
        fixtureDir: string,
        checkId: string,
        scanner: Scanner,
        preFixIssues: ScanResult[],
    ): Promise<RescanResult> {
        let validationError: string | undefined;
        try {
            const coordinator = new AssessCoordinator(fixtureDir, () => {});
            await coordinator.assess('Apache-2.0', false, false, false, false);
        } catch (error) {
            validationError = (error as Error).message;
        }

        const postFixIssues = this.readIssues(fixtureDir);
        const preIds = new Set(
            preFixIssues
                .filter(issue => this.matchesScanner(issue, scanner) && this.isActive(issue))
                .map(issue => issue.check_id ?? ''),
        );

        const sameScannerPost = postFixIssues.filter(issue => this.matchesScanner(issue, scanner) && this.isActive(issue));
        const targetRuleStillFires = sameScannerPost.some(issue => issue.check_id === checkId);
        const newRulesTriggered = sameScannerPost
            .map(issue => issue.check_id ?? '')
            .filter(id => id && id !== checkId && !preIds.has(id));

        return {
            targetRuleStillFires,
            newRulesTriggered: Array.from(new Set(newRulesTriggered)),
            validationPassed: validationError === undefined,
            validationError,
        };
    }

    private isActive(issue: ScanResult): boolean {
        const status = (issue.status ?? '').toLowerCase();
        return status !== 'fixed' && status !== 'resolved';
    }

    private matchesScanner(issue: ScanResult, scanner: Scanner): boolean {
        const source = (issue.source ?? '').toLowerCase();
        if (scanner === 'security-matrix') return source === 'security-matrix';
        if (scanner === 'checkov') return source === 'checkov';
        if (scanner === 'bandit') return source === 'bandit';
        if (scanner === 'semgrep') return source === 'semgrep';
        return false;
    }

    private readIssues(fixtureDir: string): ScanResult[] {
        const filePath = path.join(fixtureDir, ISSUES_FILE);
        if (!fs.existsSync(filePath)) return [];
        try {
            return JSON.parse(fs.readFileSync(filePath, 'utf8')) as ScanResult[];
        } catch {
            return [];
        }
    }
}
