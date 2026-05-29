import * as fs from 'node:fs';
import * as path from 'node:path';
import * as url from 'node:url';
import { execFileSync } from 'node:child_process';
import { RuleContext } from '../shared/rule-context.js';
import { RemediationUpdaterAgent } from './remediation-updater-agent.js';
import { RelatedRulesRecorder } from './related-rules-recorder.js';
import { FixtureType } from '../fixtures/fixture-type.js';
import type { ScanResult } from '../../../src/assess/scanning/base-scanner.js';

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

export class FixtureRemediator {
    private validationResult: FixValidationResult | null = null;
    private issues: ScanResult[] = [];
    private fixAttempt = 1;

    constructor(private readonly context: RuleContext, private readonly fixtureType: FixtureType) { }

    public async run(): Promise<void> {
        this.resetWorkflow();
        this.prepareFixtures();

        await this.testRule();
        await this.backupIssuesFile();

        for (const issue of this.issues) {
            this.resetFixAttempts();

            while (this.shouldIterate()) {
                await this.applyFix(issue);
                await this.validateFix(issue);
                if (this.fixWasSuccessful()) break;
                await this.updateFix(issue);
                this.tryAgain();
            }
        }
    }

    private resetWorkflow(): void {
        this.validationResult = null;
        this.issues = [];
        this.fixAttempt = 1;
    }

    private prepareFixtures(): void {
        fs.rmSync(this.fixtureType.outputFolderPath, { recursive: true, force: true });
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

    private runAssessment(): void {
        const runnerPath = url.fileURLToPath(new URL('./assess-runner.ts', import.meta.url));
        execFileSync(process.execPath, [runnerPath, this.fixtureType.outputFolderPath], { stdio: 'inherit' });
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
        return this.fixAttempt <= 3;
    }

    private async applyFix(issue: ScanResult): Promise<void> {
        const { FixCoordinator } = await import('../../../src/fix/coordinator.js');
        const fixer = await FixCoordinator.create(this.fixtureType.outputFolderPath, () => { });
        const fix = await fixer.generateFix(issue);
        await fixer.applyFix(issue, fix!);
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
            console.log(`  ✗ Fix did not resolve ${issue.check_id}`);
            this.validationResult = new FixValidationResult(targetIssue, false);
            return;
        }

        const keyOf = (i: ScanResult) => `${i.resourceName}::${i.check_id}`;
        const originalKeys = new Set(originalIssues.map(keyOf));
        const newIssues = currentIssues.filter(i => i.priority === 'HIGH' && i.status?.toLowerCase() === 'open' && !originalKeys.has(keyOf(i)) && !i.isCustomResource);

        if (newIssues.length > 0) {
            const ids = newIssues.map(i => i.check_id).join(', ');
            console.log(`  ✗ Fix introduced new HIGH priority issues: ${ids}`);
            this.validationResult = new FixValidationResult(targetIssue, true, newIssues);
            return;
        }

        console.log(`  ✓ Fix resolved ${this.context.ruleId} without introducing new HIGH priority issues`);
        this.validationResult = new FixValidationResult(targetIssue, true);
    }

    private fixWasSuccessful(): boolean {
        return this.validationResult?.isSuccessful ?? false;
    }

    private async updateFix(issue: ScanResult): Promise<void> {
        if (this.fixIntroducedRegressions()) {
            await this.recordRelatedRules();
            await this.refreshFixGuidance(issue);
        } else {
            issue.fix = await new RemediationUpdaterAgent(this.context, this.fixtureType).invoke(this.validationResult!);
        }
    }

    private fixIntroducedRegressions(): boolean {
        return !!this.validationResult?.fixedOriginalFinding && this.validationResult.introducedRegressions;
    }

    private async recordRelatedRules(): Promise<void> {
        const triggeredCheckIds = this.validationResult!.introducedFindings.map(f => f.check_id!).filter(Boolean);
        await new RelatedRulesRecorder(this.context).record(triggeredCheckIds);
    }

    private async refreshFixGuidance(issue: ScanResult): Promise<void> {
        this.prepareFixtures();
        this.runAssessment();
        await this.backupIssuesFile();
        const refreshed = (await this.loadIssues()).find(i => i.check_id === issue.check_id && i.resourceName === issue.resourceName);
        if (refreshed) issue.fix = refreshed.fix;
    }

    private tryAgain(): void {
        this.fixAttempt++;
    }
}
