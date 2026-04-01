import * as path from 'path';
import * as fs from 'fs';
import { IssueReader } from '../shared/issues/issue-reader.js';
import { ProjectSettingsManager } from '../shared/project/project-settings-manager.js';
import { DashboardGenerator } from './dashboard/dashboard-generator.js';
import { ProjectContext } from '../shared/project/project-context.js';
import { IgnorePatternService } from '../shared/file-system/ignore-pattern-service.js';
import { PostHogClient } from '../shared/analytics/posthog-client.js';
import { AppConfig } from '../shared/app-config/app-config.js';

export interface StatusResult {
    license: string;
    lastScanDate: Date | null;
    openIssues: number;
    reopenedIssues: number;
    fixedIssues: number;
    suppressedIssues: number;
    totalIssues: number;
    completionRate: number;
    dashboardPath: string | null;
}

export interface GetStatusOptions {
    showAll?: boolean;
}

export class StatusCoordinator {
    private readonly issueReader: IssueReader;
    private readonly dashboardGenerator = new DashboardGenerator();
    private readonly context: ProjectContext;
    private readonly settingsManager: ProjectSettingsManager;

    private constructor(context: ProjectContext) {
        this.context = context;
        this.settingsManager = new ProjectSettingsManager(this.context);
        this.issueReader = new IssueReader(this.context);
    }

    public static async create(projectRootFolderPath: string): Promise<StatusCoordinator> {
        const ignorePatternService = await IgnorePatternService.create(projectRootFolderPath);
        const context = new ProjectContext(projectRootFolderPath, ignorePatternService);
        const coordinator = new StatusCoordinator(context);

        const projectId = await coordinator.settingsManager.ensureProjectId();
        const installationId = AppConfig.getInstallationId();
        if (installationId && AppConfig.isTelemetryEnabled()) {
            PostHogClient.initialize(installationId, projectId);
        }

        return coordinator;
    }

    public async getStatus(options?: GetStatusOptions): Promise<StatusResult> {
        const projectRootFolderPath = this.context.getProjectRootFolderPath();
        const settings = await this.settingsManager.loadSettings();
        const showAll = options?.showAll ?? false;

        const openIssues = (await this.issueReader.getIssues('high', 'open')).length;
        const reopenedIssues = (await this.issueReader.getIssues('high', 'reopened')).length;
        const fixedIssues = (await this.issueReader.getIssues('high', 'fixed')).length;
        const suppressedIssues = (await this.issueReader.getIssues('high', 'suppressed')).length;
        const totalIssues = openIssues + reopenedIssues + fixedIssues + suppressedIssues;
        const completionRate = totalIssues === 0 ? 100 : Math.round(((fixedIssues + suppressedIssues) / totalIssues) * 100);

        const dashboardPath = await this.generateDashboard(this.context.getSrtOutputFolderPath(), projectRootFolderPath, settings?.LAST_SCAN_DATE, showAll);

        const hasBlocking = openIssues > 0 || reopenedIssues > 0;
        PostHogClient.captureStatusViewed({
            open_issues: openIssues + reopenedIssues,
            has_blocking: hasBlocking
        });

        return {
            license: settings?.LICENSE || 'None',
            lastScanDate: settings?.LAST_SCAN_DATE ? new Date(settings.LAST_SCAN_DATE) : null,
            openIssues,
            reopenedIssues,
            fixedIssues: fixedIssues,
            suppressedIssues,
            totalIssues,
            completionRate,
            dashboardPath
        };
    }

    private async generateDashboard(srtFolderPath: string, projectPath: string, lastScanDate: string | undefined, showAll: boolean): Promise<string | null> {
        if (!fs.existsSync(srtFolderPath)) {
            return null;
        }

        const issuesPath = path.join(srtFolderPath, 'issues.json');
        if (!fs.existsSync(issuesPath)) {
            return null;
        }

        return this.dashboardGenerator.generate({
            srtFolderPath,
            projectName: path.basename(projectPath),
            scanDate: lastScanDate ? new Date(lastScanDate) : new Date(),
            showAll
        });
    }
}
