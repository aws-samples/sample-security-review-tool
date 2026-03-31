import { readJsonFile, fileExists } from '../../shared/file-system/file-utils.js';
import { ScanResult } from '../scanning/types.js';
import { ReportingOptions } from './types.js';
import { ProjectContext } from '../../shared/project/project-context.js';

type IssueMatcher = (existing: ScanResult, newIssue: ScanResult) => boolean;

export class IssueAggregator {
    constructor(private readonly context: ProjectContext) { }

    public async aggregateResults(options: ReportingOptions): Promise<ScanResult[]> {
        const issues = await this.loadExistingIssues();
        const existingIssueCount = issues.length;
        const matchedIndices = new Set<number>();

        await this.processSemgrepIssues(options, issues, matchedIndices);
        await this.processBanditIssues(options, issues, matchedIndices);
        await this.processTemplateIssues(options, issues, matchedIndices);

        this.markUnmatchedIssuesAsResolved(issues, existingIssueCount, matchedIndices);

        return issues;
    }

    private async loadExistingIssues(): Promise<ScanResult[]> {
        const issuesFilePath = this.context.getIssuesFilePath();
        if (await fileExists(issuesFilePath)) {
            const issuesData = await readJsonFile<ScanResult[]>(issuesFilePath);
            if (issuesData) {
                return issuesData;
            }
        }
        return [];
    }

    private async processSemgrepIssues(options: ReportingOptions, issues: ScanResult[], matchedIndices: Set<number>): Promise<void> {
        const semgrepIssues = await readJsonFile<ScanResult[]>(options.codeScanResult.semgrepSummaryPath);
        if (!semgrepIssues) return;

        const matcher: IssueMatcher = (existing, newIssue) =>
            existing.path === newIssue.path &&
            existing.line === newIssue.line &&
            existing.issue === newIssue.issue;

        this.mergeIssues(semgrepIssues, issues, matchedIndices, matcher);
    }

    private async processBanditIssues(options: ReportingOptions, issues: ScanResult[], matchedIndices: Set<number>): Promise<void> {
        if (!options.codeScanResult.banditSummaryPath) return;

        const banditIssues = await readJsonFile<ScanResult[]>(options.codeScanResult.banditSummaryPath);
        if (!banditIssues) return;

        const matcher: IssueMatcher = (existing, newIssue) =>
            existing.path === newIssue.path &&
            existing.line === newIssue.line &&
            existing.check_id === newIssue.check_id;

        this.mergeIssues(banditIssues, issues, matchedIndices, matcher);
    }

    private async processTemplateIssues(options: ReportingOptions, issues: ScanResult[], matchedIndices: Set<number>): Promise<void> {
        for (const templateResult of options.templateResults) {
            await this.processCheckovIssues(templateResult.checkovSummaryPath, issues, matchedIndices);
            await this.processSecurityMatrixIssues(templateResult.securityMatrixPath, issues, matchedIndices);
        }
    }

    private async processCheckovIssues(checkovSummaryPath: string | null, issues: ScanResult[], matchedIndices: Set<number>): Promise<void> {
        if (!checkovSummaryPath) return;

        const checkovIssues = await readJsonFile<ScanResult[]>(checkovSummaryPath);
        if (!checkovIssues) return;

        const matcher: IssueMatcher = (existing, newIssue) =>
            existing.path === newIssue.path &&
            existing.line === newIssue.line &&
            existing.check_id === newIssue.check_id;

        this.mergeIssues(checkovIssues, issues, matchedIndices, matcher);
    }

    private async processSecurityMatrixIssues(securityMatrixPath: string | null, issues: ScanResult[], matchedIndices: Set<number>): Promise<void> {
        if (!securityMatrixPath) return;

        const securityMatrixIssues = await readJsonFile<ScanResult[]>(securityMatrixPath);
        if (!securityMatrixIssues) return;

        const matcher: IssueMatcher = (existing, newIssue) =>
            existing.path === newIssue.path &&
            existing.resourceType === newIssue.resourceType &&
            existing.resourceName === newIssue.resourceName &&
            existing.check_id === newIssue.check_id;

        this.mergeIssues(securityMatrixIssues, issues, matchedIndices, matcher);
    }

    private mergeIssues(newIssues: ScanResult[], issues: ScanResult[], matchedIndices: Set<number>, matcher: IssueMatcher): void {
        for (const newIssue of newIssues) {
            const existingIndex = issues.findIndex(existing => matcher(existing, newIssue));

            if (existingIndex === -1) {
                issues.push(newIssue);
            } else {
                matchedIndices.add(existingIndex);
                this.reopenIfPreviouslyFixed(issues[existingIndex]);
            }
        }
    }

    private reopenIfPreviouslyFixed(issue: ScanResult): void {
        if (issue.status === 'fixed' || issue.status === 'resolved') {
            issue.status = 'reopened';
        }
    }

    private markUnmatchedIssuesAsResolved(issues: ScanResult[], existingIssueCount: number, matchedIndices: Set<number>): void {
        for (let i = 0; i < existingIssueCount; i++) {
            if (matchedIndices.has(i)) continue;

            const status = issues[i].status?.toLowerCase();
            if (status === 'open' || status === 'suppressed' || status === 'reopened') {
                issues[i].status = 'resolved';
            }
        }
    }
}
