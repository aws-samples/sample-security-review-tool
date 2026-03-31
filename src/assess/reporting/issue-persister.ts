import * as path from 'path';
import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { readJsonFile, writeJsonFile, ensureDirectoryExists, fileExists } from '../../shared/file-system/file-utils.js';
import { ScanResult } from '../scanning/types.js';

export class IssuePersister {
    public async saveIssues(issues: ScanResult[], outputPath: string): Promise<void> {
        try {
            await ensureDirectoryExists(path.dirname(outputPath));
            await writeJsonFile(outputPath, issues);
        } catch (error) {
            SrtLogger.logError('Error saving issues', error as Error, { outputPath });
            throw error;
        }
    }

    public async loadIssues(outputPath: string): Promise<ScanResult[]> {
        try {
            if (!(await fileExists(outputPath))) {
                return [];
            }

            const issues = await readJsonFile<ScanResult[]>(outputPath);
            return issues || [];
        } catch (error) {
            SrtLogger.logError('Error loading issues', error as Error, { outputPath });
            return [];
        }
    }

    public async getIssuesByPriority(outputPath: string, priority: 'high' | 'medium' | 'low'): Promise<ScanResult[]> {
        const issues = await this.loadIssues(outputPath);
        return issues.filter(issue => issue.priority?.toLowerCase() === priority);
    }

    public async getIssuesByStatus(outputPath: string, status: string): Promise<ScanResult[]> {
        const issues = await this.loadIssues(outputPath);
        return issues.filter(issue => issue.status?.toLowerCase() === status.toLowerCase());
    }

    public async updateIssueStatus(outputPath: string, issueId: string, newStatus: string): Promise<void> {
        try {
            const issues = await this.loadIssues(outputPath);
            const issueIndex = issues.findIndex(issue => issue.check_id === issueId);

            if (issueIndex === -1) {
                return;
            }

            issues[issueIndex].status = newStatus;
            await this.saveIssues(issues, outputPath);
        } catch (error) {
            SrtLogger.logError('Error updating issue status', error as Error, { outputPath, issueId });
            throw error;
        }
    }
}
