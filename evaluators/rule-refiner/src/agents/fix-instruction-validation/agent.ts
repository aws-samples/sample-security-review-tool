import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { AssessCoordinator } from '../../../../../src/assess/coordinator.js';
import { FixCoordinator } from '../../../../../src/fix/coordinator.js';
import type { ScanResult } from '../../../../../src/assess/scanning/types.js';
import type { FixInstructionValidationResult } from '../types.js';

export interface FixInstructionValidationInput {
    fixtureDir: string;
    checkId: string;
    variantId: string;
    formatVariant: string;
    fixGuidanceOverride?: string;
}

export class FixInstructionValidationAgent {

    public async invoke(input: FixInstructionValidationInput): Promise<FixInstructionValidationResult> {
        const { fixtureDir, checkId, variantId, formatVariant, fixGuidanceOverride } = input;

        const scanResult = await this.scan(fixtureDir, checkId);
        if (!scanResult.success) {
            return {
                variantId,
                formatVariant,
                scanFoundIssue: false,
                scanError: scanResult.error,
                fixGenerated: false,
                fixResolved: false,
                newIssuesIntroduced: [],
                failureDetails: `Scan failed: ${scanResult.error}`,
            };
        }

        if (!scanResult.targetFinding) {
            return {
                variantId,
                formatVariant,
                scanFoundIssue: false,
                fixGenerated: false,
                fixResolved: false,
                newIssuesIntroduced: [],
                failureDetails: 'Fixture did not trigger the target rule',
            };
        }

        if (fixGuidanceOverride) {
            scanResult.targetFinding.fix = fixGuidanceOverride;
        }

        const fixResult = await this.applyFix(fixtureDir, scanResult.targetFinding);
        if (!fixResult.success) {
            this.resetFixture(fixtureDir);
            return {
                variantId,
                formatVariant,
                scanFoundIssue: true,
                fixGenerated: false,
                fixResolved: false,
                fixError: fixResult.error,
                newIssuesIntroduced: [],
                failureDetails: `Fix failed: ${fixResult.error}`,
            };
        }

        const rescanResult = await this.rescan(fixtureDir, checkId, scanResult.preFixIssues);
        this.resetFixture(fixtureDir);

        return {
            variantId,
            formatVariant,
            scanFoundIssue: true,
            fixGenerated: true,
            fixResolved: !rescanResult.targetStillFires,
            newIssuesIntroduced: rescanResult.newIssues,
            failureDetails: rescanResult.targetStillFires
                ? 'Fix did not resolve the finding'
                : rescanResult.newIssues.length > 0
                    ? `Fix introduced new issues: ${rescanResult.newIssues.join(', ')}`
                    : undefined,
        };
    }

    private async scan(fixtureDir: string, checkId: string): Promise<{
        success: boolean;
        error?: string;
        targetFinding?: ScanResult;
        preFixIssues: ScanResult[];
    }> {
        const coordinator = new AssessCoordinator(fixtureDir, () => {});
        try {
            await coordinator.assess('Apache-2.0', false, false, false, false);
        } catch (error) {
            return { success: false, error: (error as Error).message, preFixIssues: [] };
        }

        const issues = this.readActiveIssues(fixtureDir);
        const targetFinding = issues.find(i => i.check_id === checkId);

        return {
            success: true,
            targetFinding: targetFinding ?? undefined,
            preFixIssues: issues,
        };
    }

    private async applyFix(fixtureDir: string, issue: ScanResult): Promise<{ success: boolean; error?: string }> {
        let coordinator: FixCoordinator;
        try {
            coordinator = await FixCoordinator.create(fixtureDir, () => {});
        } catch (error) {
            return { success: false, error: `FixCoordinator.create failed: ${(error as Error).message}` };
        }

        try {
            const fix = await coordinator.generateFix(issue);
            if (!fix) {
                return { success: false, error: 'Fix agent could not generate a fix' };
            }
            await coordinator.applyFix(issue, fix);
            return { success: true };
        } catch (error) {
            return { success: false, error: (error as Error).message };
        }
    }

    private async rescan(fixtureDir: string, checkId: string, preFixIssues: ScanResult[]): Promise<{
        targetStillFires: boolean;
        newIssues: string[];
    }> {
        const coordinator = new AssessCoordinator(fixtureDir, () => {});
        try {
            await coordinator.assess('Apache-2.0', false, false, false, false);
        } catch {
            return { targetStillFires: true, newIssues: [] };
        }

        const postFixIssues = this.readActiveIssues(fixtureDir);
        const targetStillFires = postFixIssues.some(i => i.check_id === checkId);

        const issueKey = (i: ScanResult) => `${i.check_id}::${i.resourceName}`;
        const preIssueKeys = new Set(preFixIssues.map(issueKey));
        const newIssues = postFixIssues
            .filter(i => !preIssueKeys.has(issueKey(i)))
            .map(i => `${i.check_id} on ${i.resourceName}`);

        return { targetStillFires, newIssues };
    }

    private readActiveIssues(projectPath: string): ScanResult[] {
        const issuesPath = path.join(projectPath, '.srt', 'issues.json');
        if (!fs.existsSync(issuesPath)) return [];
        try {
            const issues = JSON.parse(fs.readFileSync(issuesPath, 'utf8')) as ScanResult[];
            return issues.filter(i => i.status !== 'fixed' && i.status !== 'resolved');
        } catch {
            return [];
        }
    }

    private resetFixture(fixtureDir: string): void {
        try {
            execSync('git reset --hard HEAD', { cwd: fixtureDir, stdio: 'ignore' });
            execSync('git clean -fdxq', { cwd: fixtureDir, stdio: 'ignore' });
        } catch {
            // Best-effort reset
        }
    }
}
