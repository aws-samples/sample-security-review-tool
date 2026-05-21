import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import { RemediationUpdaterAgent } from './remediation-updater-agent.js';
import { AssessCoordinator } from '../../../../src/assess/coordinator.js';
import { ScanResult } from '../../../../src/assess/scanning/base-scanner.js';
import { FixCoordinator } from '../../../../src/fix/coordinator.js';

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

export class RemediationWorkflow {
    private validationResult: FixValidationResult | null = null;
    private attempt = 1;

    constructor(private readonly context: RuleContext) { }

    public async run(): Promise<void> {
        this.resetWorkflow();

        while (this.shouldIterate()) {
            await this.prepareFixtures();
            await this.testRule();
            await this.validateRuleTriggered();
            await this.backupIssuesFile();
            await this.applyFix();
            await this.validateFix();

            if (this.fixWasSuccessful()) return;

            await this.updateFixInstructions();
            this.tryAgain();
        }
    }

    private resetWorkflow(): void {
        this.validationResult = null;
        this.attempt = 1;
    }

    private shouldIterate(): boolean {
        return this.attempt <= 3;
    }

    private async prepareFixtures(): Promise<void> {
        if (this.isFirstAttempt()) await fs.promises.rm(this.context.rootFixtureFolderPath, { recursive: true, force: true });                

        await fs.promises.mkdir(this.context.cdkFixtureFolderPath, { recursive: true });
        await fs.promises.mkdir(this.context.terraformFixtureFolderPath, { recursive: true });
        await fs.promises.mkdir(this.context.cloudFormationFixtureFolderPath, { recursive: true });

        const cdkTemplatePath = path.join(this.context.srtRootFolderPath, 'evaluators/rule-implementer/src/remediation/templates/cdk');
        const terraformTemplatePath = path.join(this.context.srtRootFolderPath, 'evaluators/rule-implementer/src/remediation/templates/terraform');
        const cfnTemplatePath = path.join(this.context.srtRootFolderPath, 'evaluators/rule-implementer/src/remediation/templates/cfn');

        fs.cpSync(cdkTemplatePath, this.context.cdkFixtureFolderPath, { recursive: true });
        fs.cpSync(terraformTemplatePath, this.context.terraformFixtureFolderPath, { recursive: true });
        fs.cpSync(cfnTemplatePath, this.context.cloudFormationFixtureFolderPath, { recursive: true });
    }

    private isFirstAttempt(): boolean {
        return this.attempt === 1;
    }

    private async testRule() {
        const assessor = new AssessCoordinator(this.context.cdkFixtureFolderPath, () => { });
        await assessor.assess('aws', false, false, false);
    }

    private async validateRuleTriggered(): Promise<void> {
        const issuesPath = path.join(this.context.cdkFixtureFolderPath, '.srt', 'issues.json');
        const issuesData = await fs.promises.readFile(issuesPath, 'utf-8');
        const issues: ScanResult[] = JSON.parse(issuesData);

        if (issues.every(x => x.check_id !== this.context.ruleId)) {
            throw new Error(`Rule did not trigger on initial fixture. Please check the fixture and rule implementation.`);
        }
    }

    private async backupIssuesFile(): Promise<void> {
        if (this.attempt !== 1) return;
        
        const issuesPath = path.join(this.context.cdkFixtureFolderPath, '.srt', 'issues.json');
        await fs.promises.copyFile(issuesPath, issuesPath.replace('.json', '.original.json'));
    }

    private async applyFix(): Promise<void> {
        const fixer = await FixCoordinator.create(this.context.cdkFixtureFolderPath, () => { });
        const issuesPath = path.join(this.context.cdkFixtureFolderPath, '.srt', 'issues.json');
        const issuesData = await fs.promises.readFile(issuesPath, 'utf-8');
        const issues: ScanResult[] = JSON.parse(issuesData);
        const issue = issues.find(x => x.check_id === this.context.ruleId);

        const fix = await fixer.generateFix(issue!);
        await fixer.applyFix(issue!, fix!);
    }

    private async validateFix(): Promise<void> {
        await this.testRule();

        const issuesPath = path.join(this.context.cdkFixtureFolderPath, '.srt', 'issues.json');
        const originalPath = issuesPath.replace('.json', '.original.json');

        const [currentData, originalData] = await Promise.all([
            fs.promises.readFile(issuesPath, 'utf-8'),
            fs.promises.readFile(originalPath, 'utf-8'),
        ]);

        const currentIssues: ScanResult[] = JSON.parse(currentData);
        const originalIssues: ScanResult[] = JSON.parse(originalData);

        const targetIssue = currentIssues.find(i => i.check_id === this.context.ruleId);

        if (!targetIssue) throw new Error(`After applying the fix, the original issue (${this.context.ruleId}) is no longer detected, which is unexpected. Please investigate the fix and the test fixture.`);

        if (targetIssue.status?.toLowerCase() !== 'fixed') {
            console.log(`  ✗ Fix did not resolve ${this.context.ruleId}`);
            this.validationResult = new FixValidationResult(targetIssue, false);
        }

        const originalCheckIds = new Set(originalIssues.map(i => i.check_id));
        const newIssues = currentIssues.filter(i => i.priority === 'HIGH' && i.status?.toLowerCase() === 'open' && !originalCheckIds.has(i.check_id) && !i.isCustomResource);

        if (newIssues.length > 0) {
            const ids = newIssues.map(i => i.check_id).join(', ');
            console.log(`  ✗ Fix introduced new HIGH priority issues: ${ids}`);
            this.validationResult = new FixValidationResult(targetIssue, true, newIssues);
        }

        console.log(`  ✓ Fix resolved ${this.context.ruleId} without introducing new HIGH priority issues`);
        this.validationResult = new FixValidationResult(targetIssue, true);
    }

    private fixWasSuccessful(): boolean {
        return this.validationResult?.isSuccessful ?? false;
    }

    private async updateFixInstructions(): Promise<void> {
        await new RemediationUpdaterAgent(this.context).invoke(this.validationResult!);
    }

    private tryAgain(): void {
        this.attempt++;
    }
}
