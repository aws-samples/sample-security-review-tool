import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { writeJsonFile } from '../../shared/file-system/file-utils.js';
import { ReportingOptions, AssessmentSummary } from './types.js';
import { IssueAggregator } from './issue-aggregator.js';
import { ExcelReportWriter } from './excel-report-writer.js';
import { ProjectContext } from '../../shared/project/project-context.js';
import { ScanResult } from '../scanning/types.js';

export class ReportGenerator {
    constructor(private readonly context: ProjectContext, private readonly onProgress: (progress: string) => void = () => { }) { }

    public async generateReports(options: ReportingOptions): Promise<AssessmentSummary | null> {
        try {
            const summary = await this.consolidateIssues(options);

            if (options.generateXlsx) {
                this.onProgress('  › Creating Excel report...');
                try {
                    const excelWriter = new ExcelReportWriter();
                    await excelWriter.write({
                        srtOutputFolderPath: this.context.getSrtOutputFolderPath(),
                        codeScanResult: options.codeScanResult,
                        templateResults: options.templateResults
                    });
                    this.onProgress('  ✔ Created Excel report');
                } catch (error) {
                    this.onProgress('  ✗ Failed to create Excel report');
                    SrtLogger.logError('Error creating Excel report', error as Error, { projectName: this.context.getProjectName() });
                }
            }

            return summary;
        } catch (error) {
            SrtLogger.logError('Error during report generation', error as Error, { projectName: this.context.getProjectName() });
            return null;
        }
    }

    private async consolidateIssues(options: ReportingOptions): Promise<AssessmentSummary | null> {
        try {
            this.onProgress('  › Consolidating issues...');
            const aggregator = new IssueAggregator(this.context);
            const result = await aggregator.aggregateResults(options);
            const issuesFilePath = this.context.getIssuesFilePath();

            await writeJsonFile(issuesFilePath, result.issues);
            this.onProgress('  ✔ Consolidated issues');
            return result.summary;
        } catch (error) {
            this.onProgress('  ✗ Failed to consolidate issues');
            SrtLogger.logError('Error consolidating issues', error as Error, { projectName: this.context.getProjectName() });
            return null;
        }
    }
}
