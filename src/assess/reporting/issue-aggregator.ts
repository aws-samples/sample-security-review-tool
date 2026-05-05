import { readJsonFile, fileExists } from '../../shared/file-system/file-utils.js';
import { ScanResult } from '../scanning/types.js';
import { ReportingOptions, AssessmentSummary } from './types.js';
import { ProjectContext } from '../../shared/project/project-context.js';
import { PostHogClient } from '../../shared/analytics/posthog-client.js';

type IssueMatcher = (existing: ScanResult, newIssue: ScanResult) => boolean;

export interface AggregationResult {
    issues: ScanResult[];
    summary: AssessmentSummary;
}

export class IssueAggregator {
    private newIssueCount = 0;
    private resolvedIssueCount = 0;
    private reopenedIssueCount = 0;

    constructor(private readonly context: ProjectContext) { }

    public async aggregateResults(options: ReportingOptions): Promise<AggregationResult> {
        this.newIssueCount = 0;
        this.resolvedIssueCount = 0;
        this.reopenedIssueCount = 0;

        const issues = await this.loadExistingIssues();
        const existingIssueCount = issues.length;
        const matchedIndices = new Set<number>();

        await this.processSemgrepIssues(options, issues, matchedIndices);
        await this.processBanditIssues(options, issues, matchedIndices);
        await this.processTemplateIssues(options, issues, matchedIndices);
        await this.processTerraformIssues(options, issues, matchedIndices);

        this.markUnmatchedIssuesAsResolved(issues, existingIssueCount, matchedIndices);

        const summary = this.calculateSummary(issues);
        return { issues, summary };
    }

    private calculateSummary(issues: ScanResult[]): AssessmentSummary {
        const bySource: Record<string, number> = {};
        let highPriority = 0;
        let mediumPriority = 0;
        let lowPriority = 0;

        for (const issue of issues) {
            const source = issue.source.toLowerCase().replace('-', '_');
            bySource[source] = (bySource[source] || 0) + 1;

            const priority = issue.priority?.toUpperCase();
            if (priority === 'HIGH') highPriority++;
            else if (priority === 'MEDIUM') mediumPriority++;
            else if (priority === 'LOW') lowPriority++;
        }

        return {
            totalIssues: issues.length,
            newIssues: this.newIssueCount,
            resolvedIssues: this.resolvedIssueCount,
            reopenedIssues: this.reopenedIssueCount,
            highPriority,
            mediumPriority,
            lowPriority,
            bySource
        };
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

    private async processTerraformIssues(options: ReportingOptions, issues: ScanResult[], matchedIndices: Set<number>): Promise<void> {
        if (!options.terraformResults) return;

        for (const tfResult of options.terraformResults) {
            await this.processCheckovIssues(tfResult.checkovSummaryPath, issues, matchedIndices);
            await this.processSecurityMatrixIssues(tfResult.terraformMatrixPath, issues, matchedIndices);
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
                newIssue.firstDetectedAt = new Date().toISOString();
                newIssue.assessmentCount = 1;
                newIssue.status = newIssue.status || 'open';
                issues.push(newIssue);
                this.newIssueCount++;
                this.captureIssueDetected(newIssue);
            } else {
                const existingIssue = issues[existingIndex];
                existingIssue.assessmentCount = (existingIssue.assessmentCount || 1) + 1;
                matchedIndices.add(existingIndex);
                this.reopenIfPreviouslyFixed(existingIssue);
            }
        }
    }

    private captureIssueDetected(issue: ScanResult): void {
        PostHogClient.captureIssueDetected({
            check_id: issue.check_id || 'unknown',
            description: issue.issue || 'No description',
            priority: issue.priority || 'unknown',
            source: issue.source,
            resource_type: issue.resourceType
        });
    }

    private reopenIfPreviouslyFixed(issue: ScanResult): void {
        if (issue.status === 'fixed' || issue.status === 'resolved') {
            const daysResolved = this.calculateDaysSince(issue.resolvedAt);
            issue.status = 'reopened';
            issue.resolvedAt = undefined;
            this.reopenedIssueCount++;
            this.captureIssueReopened(issue, daysResolved);
        }
    }

    private captureIssueReopened(issue: ScanResult, daysResolved: number): void {
        PostHogClient.captureIssueReopened({
            check_id: issue.check_id || 'unknown',
            description: issue.issue || 'No description',
            priority: issue.priority || 'unknown',
            source: issue.source,
            resource_type: issue.resourceType,
            days_resolved: daysResolved
        });
    }

    private markUnmatchedIssuesAsResolved(issues: ScanResult[], existingIssueCount: number, matchedIndices: Set<number>): void {
        for (let i = 0; i < existingIssueCount; i++) {
            if (matchedIndices.has(i)) continue;

            const issue = issues[i];
            const status = issue.status?.toLowerCase();
            if (status === 'open' || status === 'suppressed' || status === 'reopened') {
                issue.status = 'resolved';
                issue.resolvedAt = new Date().toISOString();
                this.resolvedIssueCount++;
                this.captureIssueResolved(issue);
            }
        }
    }

    private captureIssueResolved(issue: ScanResult): void {
        const daysOpen = this.calculateDaysSince(issue.firstDetectedAt);
        PostHogClient.captureIssueResolved({
            check_id: issue.check_id || 'unknown',
            description: issue.issue || 'No description',
            priority: issue.priority || 'unknown',
            source: issue.source,
            resource_type: issue.resourceType,
            days_open: daysOpen,
            assessments_open: issue.assessmentCount || 1
        });
    }

    private calculateDaysSince(isoDateString?: string): number {
        if (!isoDateString) return 0;
        const pastDate = new Date(isoDateString);
        const now = new Date();
        const diffMs = now.getTime() - pastDate.getTime();
        return Math.floor(diffMs / (1000 * 60 * 60 * 24));
    }
}
