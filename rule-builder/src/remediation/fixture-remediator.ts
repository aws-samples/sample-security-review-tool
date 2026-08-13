import * as fs from 'node:fs';
import * as path from 'node:path';
import * as url from 'node:url';
import { spawnSync } from 'node:child_process';
import { RuleContext } from '../shared/rule-context.js';
import { FixtureDependencyInstaller } from '../shared/fixture-dependency-installer.js';
import { RemediationUpdaterAgent } from './remediation-updater-agent.js';
import { RelatedRulesRecorder } from './related-rules-recorder.js';
import { FixtureType } from '../fixtures/fixture-type.js';
import type { ScanResult } from '../../../src/assess/scanning/base-scanner.js';
import { FixValidationResult } from './fix-validation-result.js';
import { RemediationReporter } from './remediation-reporter.js';

const MAX_FIX_ATTEMPTS = 5;

export class FixtureRemediator {
    private validationResult: FixValidationResult | null = null;
    private issues: ScanResult[] = [];
    private fixAttempt = 1;

    constructor(private readonly context: RuleContext, private readonly fixtureType: FixtureType, private readonly reporter: RemediationReporter) { }

    public async run(): Promise<number> {
        this.resetWorkflow();
        this.reporter.fixtureStart(this.fixtureType);
        this.prepareFixtures();

        this.reporter.triggerCheckStart(this.context.ruleId);
        await this.testRule();
        await this.backupIssuesFile();
        this.reporter.triggerCheckPassed(this.issues.length);

        for (const issue of this.issues) {
            this.resetFixAttempts();

            while (this.shouldIterate()) {
                this.reportFixAttempt(issue);
                await this.applyFix(issue);
                await this.validateFix(issue);
                this.reportValidationOutcome();
                if (this.fixWasSuccessful()) break;
                await this.updateFix(issue);
                this.tryAgain();
            }

            this.failIfUnresolved(issue);
        }

        return this.issues.length;
    }

    private resetWorkflow(): void {
        this.validationResult = null;
        this.issues = [];
        this.fixAttempt = 1;
    }

    private prepareFixtures(): void {
        fs.rmSync(this.fixtureType.outputFolderPath, { recursive: true, force: true });
        this.restoreFixtureInputs();
        new FixtureDependencyInstaller(this.fixtureType.outputFolderPath, this.fixtureType.label).ensureInstalled();
    }

    private restoreFixtureInputs(): void {
        fs.cpSync(this.fixtureType.templateFolderPath, this.fixtureType.outputFolderPath, { recursive: true });
        fs.cpSync(this.fixtureType.resourceFilePath, path.join(this.fixtureType.outputFolderPath, this.fixtureType.resourceFileName));
    }

    private async testRule(): Promise<void> {
        this.runAssessment();
        const issues = await this.loadIssues();
        this.issues = issues.filter(x => x.check_id === this.context.ruleId);

        if (this.issues.length === 0) {
            throw new Error(`Rule ${this.context.ruleId} did not trigger on fixture. Check the fixture and rule implementation.`);
        }
    }

    // Output is captured, not inherited: the assess CLI narrates five phases per run, and remediation runs it repeatedly.
    private runAssessment(): void {
        const runnerPath = url.fileURLToPath(new URL('./assess-runner.ts', import.meta.url));
        const result = spawnSync(process.execPath, [runnerPath, this.fixtureType.outputFolderPath], { encoding: 'utf8' });
        if (result.status === 0) return;
        const output = (result.stdout ?? '') + (result.stderr ?? '');
        throw new Error(`Assessment of the ${this.fixtureType.label} fixture failed.\n${output}`);
    }

    private async loadIssues() {
        const issuesPath = path.join(this.fixtureType.outputFolderPath, '.srt', 'issues.json');
        const issuesData = await fs.promises.readFile(issuesPath, 'utf-8');
        const issues = JSON.parse(issuesData) as ScanResult[];
        return issues;
    }

    private async backupIssuesFile(): Promise<void> {
        const issuesPath = path.join(this.fixtureType.outputFolderPath, '.srt', 'issues.json');
        await fs.promises.copyFile(issuesPath, issuesPath.replace('.json', '.original.json'));
    }

    private resetFixAttempts(): void {
        this.fixAttempt = 1;
    }

    private shouldIterate(): boolean {
        return this.fixAttempt <= MAX_FIX_ATTEMPTS;
    }

    private reportFixAttempt(issue: ScanResult): void {
        if (this.fixAttempt === 1) return this.reporter.fixStart(issue);
        this.reporter.fixRetryStart();
    }

    private async applyFix(issue: ScanResult): Promise<void> {
        const { FixCoordinator } = await import('../../../src/fix/coordinator.js');
        const fixer = await FixCoordinator.create(this.fixtureType.outputFolderPath, () => { });
        const fix = await fixer.generateFix(issue);
        if (!fix) throw new Error(`The fix agent produced no edits for ${issue.check_id} on ${issue.resourceName} (${this.fixtureType.label} fixture). Check ~/.srt/logs for the reason it gave up.`);
        await fixer.applyFix(issue, fix);
    }

    private async validateFix(issue: ScanResult): Promise<void> {
        await this.testRule();

        const issuesPath = path.join(this.fixtureType.outputFolderPath, '.srt', 'issues.json');
        const originalPath = issuesPath.replace('.json', '.original.json');

        const [currentData, originalData] = await Promise.all([
            fs.promises.readFile(issuesPath, 'utf-8'),
            fs.promises.readFile(originalPath, 'utf-8'),
        ]);

        const currentIssues: ScanResult[] = JSON.parse(currentData);
        const originalIssues: ScanResult[] = JSON.parse(originalData);

        const targetIssue = currentIssues.find(i => i.check_id === issue.check_id && i.resourceName === issue.resourceName);

        if (!targetIssue) throw new Error(`After applying the fix, the original issue (${issue.check_id}) is no longer detected, which is unexpected. Please investigate the fix and the test fixture.`);

        if (targetIssue.status?.toLowerCase() !== 'fixed') {
            this.validationResult = new FixValidationResult(targetIssue, false);
            return;
        }

        const keyOf = (i: ScanResult) => `${i.resourceName}::${i.check_id}`;
        const originalKeys = new Set(originalIssues.map(keyOf));
        const newIssues = currentIssues.filter(i => i.priority === 'HIGH' && i.status?.toLowerCase() === 'open' && !originalKeys.has(keyOf(i)) && !i.isCustomResource);

        if (newIssues.length > 0) {
            this.validationResult = new FixValidationResult(targetIssue, true, newIssues);
            return;
        }

        this.validationResult = new FixValidationResult(targetIssue, true);
    }

    private reportValidationOutcome(): void {
        const result = this.validationResult!;
        if (result.isSuccessful) return this.reporter.fixResolved();
        if (this.fixAttempt < MAX_FIX_ATTEMPTS) return this.reporter.fixRetrying(result);
        this.reporter.fixFailed(result);
    }

    private fixWasSuccessful(): boolean {
        return this.validationResult?.isSuccessful ?? false;
    }

    private async updateFix(issue: ScanResult): Promise<void> {
        if (!this.fixIntroducedRegressions()) {
            issue.fix = await this.rewriteRemediation(this.validationResult!);
            return;
        }

        await this.snapshotRegression();
        const newlyRecorded = await this.recordRelatedRules();
        this.failIfNothingLeftToLearn(issue, newlyRecorded);
        await this.refreshFixGuidance(issue);
    }

    private failIfNothingLeftToLearn(issue: ScanResult, newlyRecorded: string[]): void {
        if (newlyRecorded.length > 0) return;

        const checkIds = this.validationResult!.introducedFindings.map(f => f.check_id).join(', ');
        throw new Error(
            `Fixing ${issue.check_id} on the ${this.fixtureType.label} fixture keeps triggering ${checkIds}, which is already recorded as a related rule. ` +
            `Its guidance is not sufficient to produce a passing fix — improve the remediation text for ${checkIds} in its fixes file.`
        );
    }

    private rewriteRemediation(result: FixValidationResult): Promise<string> {
        return new RemediationUpdaterAgent(this.context, this.fixtureType).invoke(result);
    }

    private fixIntroducedRegressions(): boolean {
        return !!this.validationResult?.fixedOriginalFinding && this.validationResult.introducedRegressions;
    }

    private async snapshotRegression(): Promise<void> {
        const issuesPath = path.join(this.fixtureType.outputFolderPath, '.srt', 'issues.json');
        const snapshotPath = issuesPath.replace('.json', `.regression-attempt-${this.fixAttempt}.json`);
        await fs.promises.copyFile(issuesPath, snapshotPath);
    }

    private recordRelatedRules(): Promise<string[]> {
        const triggeredCheckIds = this.validationResult!.introducedFindings.map(f => f.check_id!).filter(Boolean);
        return new RelatedRulesRecorder(this.context).record(triggeredCheckIds);
    }

    private async refreshFixGuidance(issue: ScanResult): Promise<void> {
        this.restoreFixtureInputs();
        this.runAssessment();
        const refreshed = (await this.loadIssues()).find(i => i.check_id === issue.check_id && i.resourceName === issue.resourceName);
        if (refreshed) issue.fix = refreshed.fix;
    }

    private tryAgain(): void {
        this.fixAttempt++;
    }

    private failIfUnresolved(issue: ScanResult): void {
        if (this.fixWasSuccessful()) return;
        throw new Error(`Could not validate remediation for ${issue.check_id} on the ${this.fixtureType.label} fixture after ${MAX_FIX_ATTEMPTS} attempts: ${this.validationResult!.failureDescription}`);
    }
}
