import * as path from 'path';
import * as fs from 'fs';
import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { ScanResult } from '../../assess/scanning/types.js';
import { IssueReader } from '../../shared/issues/issue-reader.js';
import { ProjectContext } from '../../shared/project/project-context.js';

export class IssueUpdater {
    private readonly issueReader: IssueReader;

    constructor(private readonly context: ProjectContext) {
        this.issueReader = new IssueReader(context);
     }

    public async markAsFixed(issue: ScanResult): Promise<void> {
        try {
            const issues = await this.issueReader.getIssues();

            const index = issues.findIndex(i =>
                i.path === issue.path &&
                i.line === issue.line &&
                i.resourceName === issue.resourceName &&
                i.check_id === issue.check_id
            );

            if (index !== -1) {
                issues[index].status = 'fixed';
                await this.saveIssues(issues);
            }
        } catch (error) {
            SrtLogger.logError('Error marking issue as fixed', error as Error);
            throw error;
        }
    }

    public async suppress(issue: ScanResult, reason: string): Promise<void> {
        try {
            const issues = await this.issueReader.getIssues();

            const index = issues.findIndex(i =>
                i.path === issue.path &&
                i.line === issue.line &&
                i.resourceName === issue.resourceName &&
                i.check_id === issue.check_id
            );

            if (index !== -1) {
                issues[index].status = 'suppressed';
                issues[index].suppressionReason = reason;
                await this.saveIssues(issues);
            }
        } catch (error) {
            SrtLogger.logError('Error suppressing issue', error as Error);
        }
    }

    private async saveIssues(issues: ScanResult[]): Promise<void> {
        const issuesFilePath = path.join(this.context.getSrtOutputFolderPath(), 'issues.json');

        try {
            // Async write calls cause problems with inquirer.js prompts, so using sync write here
            fs.writeFileSync(issuesFilePath, JSON.stringify(issues, null, 2), 'utf-8');
        } catch (error) {
            SrtLogger.logError('Error saving issues file', error as Error, { issuesFilePath });
        }
    }
}
