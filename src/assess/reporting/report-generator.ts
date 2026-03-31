import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { writeJsonFile } from '../../shared/file-system/file-utils.js';
import { ReportingOptions } from './types.js';
import { IssueAggregator } from './issue-aggregator.js';
import { ExcelReportWriter } from './excel-report-writer.js';
import { ProjectContext } from '../../shared/project/project-context.js';

export class ReportGenerator {
    constructor(private readonly context: ProjectContext, private readonly onProgress: (progress: string) => void = () => { }) { }

    public async generateReports(options: ReportingOptions): Promise<void> {
        try {
            await this.consolidateIssues(options);

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
        } catch (error) {
            SrtLogger.logError('Error during report generation', error as Error, { projectName: this.context.getProjectName() });
        }
    }

    private async consolidateIssues(options: ReportingOptions): Promise<void> {
        try {
            this.onProgress('  › Consolidating issues...');
            const aggregator = new IssueAggregator(this.context);
            const issues = await aggregator.aggregateResults(options);
            const issuesFilePath = this.context.getIssuesFilePath();

            await writeJsonFile(issuesFilePath, issues);
            this.onProgress('  ✔ Consolidated issues');
        } catch (error) {
            this.onProgress('  ✗ Failed to consolidate issues');
            SrtLogger.logError('Error consolidating issues', error as Error, { projectName: this.context.getProjectName() });
        }
    }
}
