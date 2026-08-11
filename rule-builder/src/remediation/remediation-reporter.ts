import { FixtureType } from '../fixtures/fixture-type.js';
import { FixValidationResult } from './fix-validation-result.js';
import type { ScanResult } from '../../../src/assess/scanning/base-scanner.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

export class RemediationReporter {
    private readonly logger = new RuleBuilderLogger();
    private itemStartedAt = 0;
    private attempts = 0;

    public fixtureStart(fixtureType: FixtureType): void {
        this.logger.group(fixtureType.label);
    }

    public triggerCheckStart(ruleId: string): void {
        this.openItem(`verifying ${ruleId} triggers`);
    }

    public triggerCheckPassed(count: number): void {
        this.logger.itemEnd(true, `${count} ${count === 1 ? 'finding' : 'findings'}`, this.elapsed());
    }

    public fixStart(issue: ScanResult): void {
        this.attempts = 1;
        this.openItem(issue.resourceName ?? 'unnamed resource');
    }

    public fixRetryStart(): void {
        this.attempts++;
        this.itemStartedAt = performance.now();
        this.logger.itemContinue();
    }

    public fixResolved(): void {
        const status = this.attempts === 1 ? 'fixed' : `fixed in ${this.attempts} attempts`;
        this.logger.itemEnd(true, status, this.elapsed());
    }

    public fixRetrying(result: FixValidationResult, nextAttempt: number, maxAttempts: number): void {
        this.logger.itemEnd(false, `${this.describeFailure(result)}, retrying ${nextAttempt}/${maxAttempts}`, this.elapsed());
    }

    public fixFailed(result: FixValidationResult): void {
        this.logger.itemEnd(false, `${this.describeFailure(result)}, gave up after ${this.attempts} attempts`, this.elapsed());
    }

    public regressionSnapshotSaved(snapshotPath: string): void {
        this.logger.itemNote(`regression snapshot: ${snapshotPath}`);
    }

    private openItem(name: string): void {
        this.itemStartedAt = performance.now();
        this.logger.itemStart(name);
    }

    private elapsed(): number {
        return performance.now() - this.itemStartedAt;
    }

    private describeFailure(result: FixValidationResult): string {
        const unresolved = result.fixedOriginalFinding ? [] : ['not resolved'];
        const regressions = result.introducedRegressions ? [`new HIGH ${this.formatIntroducedIds(result)}`] : [];
        return [...unresolved, ...regressions].join(', ');
    }

    private formatIntroducedIds(result: FixValidationResult): string {
        return result.introducedFindings.map(finding => finding.check_id).join(', ');
    }
}
