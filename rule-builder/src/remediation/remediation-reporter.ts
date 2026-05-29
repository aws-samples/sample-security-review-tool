import { FixtureType } from '../fixtures/fixture-type.js';
import { FixValidationResult } from './fix-validation-result.js';
import type { ScanResult } from '../../../src/assess/scanning/base-scanner.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

export class RemediationReporter {
    private readonly logger = new RuleBuilderLogger();

    public testingFixture(fixtureType: FixtureType): void {
        this.logger.info(`Testing ${fixtureType.label} fixture`);
    }

    public ruleTriggered(count: number, ruleId: string): void {
        this.logger.success(`Successfully triggered ${ruleId}`);
    }

    public attemptingFix(issue: ScanResult, attempt: number, maxAttempts: number): void {
        this.logger.info(`Fixing ${issue.check_id} on ${issue.resourceName} (attempt ${attempt}/${maxAttempts})`);
    }

    public fixSucceeded(result: FixValidationResult): void {
        this.logger.success(`Fix resolved ${result.targetIssue.check_id} without introducing new HIGH priority issues`);
    }

    public fixNotResolved(result: FixValidationResult): void {
        this.logger.failure(`Fix did not resolve ${result.targetIssue.check_id}`);
    }

    public fixIntroducedRegressions(result: FixValidationResult): void {
        this.logger.failure(`Fix introduced new HIGH priority issues: ${this.formatIntroducedIds(result)}`);
    }

    private formatIntroducedIds(result: FixValidationResult): string {
        return result.introducedFindings.map(finding => finding.check_id).join(', ');
    }
}
