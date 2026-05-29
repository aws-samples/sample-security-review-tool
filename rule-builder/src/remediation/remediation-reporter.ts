import { FixtureType } from '../fixtures/fixture-type.js';
import { FixValidationResult } from './fix-validation-result.js';
import type { ScanResult } from '../../../src/assess/scanning/base-scanner.js';

export class RemediationReporter {
    public testingFixture(fixtureType: FixtureType): void {
        console.log(`\nTesting ${fixtureType.label} fixture`);
    }

    public foundIssues(count: number, ruleId: string): void {
        console.log(`  Found ${count} ${ruleId} issue(s) to remediate`);
    }

    public attemptingFix(issue: ScanResult, attempt: number, maxAttempts: number): void {
        console.log(`  Fixing ${issue.check_id} on ${issue.resourceName} (attempt ${attempt}/${maxAttempts})`);
    }

    public fixSucceeded(result: FixValidationResult): void {
        console.log(`  ✓ Fix resolved ${result.targetIssue.check_id} without introducing new HIGH priority issues`);
    }

    public fixNotResolved(result: FixValidationResult): void {
        console.log(`  ✗ Fix did not resolve ${result.targetIssue.check_id}`);
    }

    public fixIntroducedRegressions(result: FixValidationResult): void {
        console.log(`  ✗ Fix introduced new HIGH priority issues: ${this.formatIntroducedIds(result)}`);
    }

    private formatIntroducedIds(result: FixValidationResult): string {
        return result.introducedFindings.map(finding => finding.check_id).join(', ');
    }
}
