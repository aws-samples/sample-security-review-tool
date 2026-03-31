import * as path from 'path';
import * as fs from 'fs';
import { NodeFileReader } from '../file-system/node-file-reader.js';
import { SrtLogger } from '../logging/srt-logger.js';
import { ScanResult } from '../../assess/scanning/types.js';
import { ProjectContext } from '../project/project-context.js';

export type IssueStatus = 'open' | 'fixed' | 'suppressed' | 'reopened' | 'resolved';
export type IssuePriority = 'low' | 'medium' | 'high';

export class IssueReader {
    private readonly fileReader = new NodeFileReader();
    private issues: ScanResult[] | null | undefined;

    constructor(private readonly context: ProjectContext) { }

    public async getIssues(priority?: IssuePriority, status?: IssueStatus): Promise<ScanResult[]> {
        if (this.issues === undefined) {
            await this.loadIssues();
        }

        try {
            let filteredIssues = this.issues || [];

            filteredIssues = filteredIssues.filter(issue => !issue.isCustomResource);

            if (priority) {
                filteredIssues = filteredIssues.filter(issue => issue.priority?.toLowerCase() === priority.toLowerCase());
            }

            if (status) {
                filteredIssues = filteredIssues.filter(issue => issue.status?.toLowerCase() === status.toLowerCase());
            }

            return filteredIssues;
        } catch (error) {
            SrtLogger.logError('Error getting issues', error as Error, { projectRootFolderPath: this.context.getProjectRootFolderPath(), priority, status });
            return [];
        }
    }

    private async loadIssues(): Promise<void> {
        const issuesFilePath = path.join(this.context.getSrtOutputFolderPath(), 'issues.json');

        try {
            if (fs.existsSync(issuesFilePath)) {
                this.issues = await this.fileReader.readJsonFile<ScanResult[]>(issuesFilePath);
            } else {
                this.issues = [];
            }
        } catch (error) {
            this.issues = null;
            SrtLogger.logError('Error reading issues file', error as Error, { issuesFilePath });
        }
    }

    public clearCache(): void {
        this.issues = undefined;
    }
}
