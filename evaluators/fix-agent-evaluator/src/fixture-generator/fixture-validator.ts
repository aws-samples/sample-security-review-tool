import * as fs from 'node:fs';
import * as path from 'node:path';
import { AssessCoordinator } from '../../../../src/assess/coordinator.js';
import type { ScanResult } from '../../../../src/assess/scanning/types.js';
import type { RuleEntry, Scanner } from '../../../shared/rule-catalog/src/index.js';
import type { ValidationResult } from './types.js';

const ISSUES_FILE = path.join('.srt', 'issues.json');

/**
 * Scans a freshly-written fixture and confirms it triggers the target rule
 * exactly once and no other rule from the same scanner. Format-specific parse
 * checks (cfn-lint, cdk synth, etc.) are delegated to SRT's own scanners — we
 * rely on the fact that an invalid template would either fail to parse or
 * produce no findings at all.
 */
export class FixtureValidator {
    public async validate(fixtureDir: string, rule: RuleEntry): Promise<ValidationResult> {
        this.resetIssuesFile(fixtureDir);

        try {
            const coordinator = new AssessCoordinator(fixtureDir, () => {});
            await coordinator.assess('Apache-2.0', false, false, false, false);
        } catch (error) {
            return {
                ok: false,
                failure: {
                    kind: 'parse',
                    message: `AssessCoordinator threw while scanning fixture`,
                    details: (error as Error).message,
                },
            };
        }

        const issues = this.readIssues(fixtureDir);
        const sameScanner = issues.filter(issue => this.matchesScanner(issue, rule.scanner));
        const targetHits = sameScanner.filter(issue => issue.check_id === rule.checkId);
        const extraHits = sameScanner.filter(issue => issue.check_id !== rule.checkId);

        if (targetHits.length === 0) {
            return {
                ok: false,
                failure: {
                    kind: 'scan-missing-target',
                    message: `Fixture did not trigger ${rule.checkId}`,
                    details: `Scanner ${rule.scanner} produced ${sameScanner.length} finding(s): ${sameScanner.map(i => i.check_id).join(', ') || 'none'}`,
                },
            };
        }
        if (targetHits.length > 1) {
            return {
                ok: false,
                failure: {
                    kind: 'scan-extra-rules',
                    message: `Fixture triggered ${rule.checkId} ${targetHits.length} times; expected exactly once`,
                },
            };
        }
        if (extraHits.length > 0) {
            return {
                ok: false,
                failure: {
                    kind: 'scan-extra-rules',
                    message: `Fixture triggered other ${rule.scanner} rules: ${extraHits.map(i => i.check_id).join(', ')}`,
                    details: `Remove the resource configurations that cause these additional findings.`,
                },
            };
        }
        return { ok: true };
    }

    private matchesScanner(issue: ScanResult, scanner: Scanner): boolean {
        const source = (issue.source ?? '').toLowerCase();
        if (scanner === 'security-matrix') return source === 'security-matrix';
        if (scanner === 'checkov') return source === 'checkov';
        if (scanner === 'bandit') return source === 'bandit';
        if (scanner === 'semgrep') return source === 'semgrep';
        return false;
    }

    private resetIssuesFile(fixtureDir: string): void {
        const filePath = path.join(fixtureDir, ISSUES_FILE);
        if (fs.existsSync(filePath)) fs.rmSync(filePath);
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
