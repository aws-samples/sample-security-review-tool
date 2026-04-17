import { ScanResult } from '../assess/scanning/types.js';
import { IssueReader } from '../shared/issues/issue-reader.js';
import { IssueFileResolver } from './issues/issue-file-resolver.js';
import { IssueUpdater } from './issues/issue-updater.js';
import { FixGenerator } from './ai-generation/fix-generator.js';
import { CodeApplicator } from './code-manipulation/code-applicator.js';
import { Progress, Fix } from './types.js';
import { IssuePriority, IssueStatus } from '../shared/issues/issue-reader.js';
import { ProjectContext } from '../shared/project/project-context.js';
import { IgnorePatternService } from '../shared/file-system/ignore-pattern-service.js';
import { PostHogClient } from '../shared/analytics/posthog-client.js';
import { AppConfig } from '../shared/app-config/app-config.js';
import { ProjectSettingsManager } from '../shared/project/project-settings-manager.js';
import { BedrockConfig } from '../config/aws/bedrock-config.js';
import { DsrMigrator } from '../shared/project/dsr-migrator.js';

export class FixCoordinator {
    private readonly issueReader: IssueReader;
    private readonly issueUpdater: IssueUpdater;
    private readonly fixGenerator: FixGenerator;
    private readonly issueFileResolver: IssueFileResolver;
    private readonly codeApplicator: CodeApplicator;
    private readonly context: ProjectContext;

    private constructor(context: ProjectContext, private readonly onProgress: (progress: Progress) => void) {
        this.context = context;
        this.issueFileResolver = new IssueFileResolver(this.context);
        this.issueUpdater = new IssueUpdater(this.context);
        this.codeApplicator = new CodeApplicator(this.context, this.issueUpdater);
        this.fixGenerator = new FixGenerator(this.context);
        this.issueReader = new IssueReader(this.context);
    }

    public static async create(projectRootFolderPath: string, onProgress: (progress: Progress) => void): Promise<FixCoordinator> {
        await new DsrMigrator(projectRootFolderPath).migrate();

        const ignorePatternService = await IgnorePatternService.create(projectRootFolderPath);
        const context = new ProjectContext(projectRootFolderPath, ignorePatternService);

        const projectSettingsManager = new ProjectSettingsManager(context);
        const projectId = await projectSettingsManager.ensureProjectId();
        const installationId = AppConfig.getInstallationId();
        if (installationId && AppConfig.isTelemetryEnabled()) {
            PostHogClient.initialize(installationId, projectId);
        }

        return new FixCoordinator(context, onProgress);
    }

    public async getIssues(priority: IssuePriority, status: IssueStatus): Promise<ScanResult[]> {
        this.onProgress({ phase: 'loading', details: 'Loading issues' });
        const issues = await this.issueReader.getIssues(priority, status);
        return issues;
    }

    public async getCodeFilePath(issue: ScanResult): Promise<string | null> {
        const filePath = await this.issueFileResolver.getCodeFilePath(issue);
        return filePath;
    }

    public async generateFix(issue: ScanResult): Promise<Fix | null> {
        this.onProgress({ phase: 'generating', details: 'Generating fix suggestion' });
        const fix = await this.fixGenerator.generateFix(issue);
        if (fix) {
            this.captureFixGenerated(issue);
        }
        return fix;
    }

    private captureFixGenerated(issue: ScanResult): void {
        PostHogClient.captureFixGenerated({
            check_id: issue.check_id || 'unknown',
            description: issue.issue || 'unknown',
            priority: issue.priority || 'unknown',
            source: issue.source,
            resource_type: issue.resourceType,
            model: BedrockConfig.getModel().name
        });
    }

    public async applyFix(issue: ScanResult, fix: Fix): Promise<void> {
        this.onProgress({ phase: 'applying', details: 'Applying fix to code' });
        await this.codeApplicator.applyFix(issue, fix);
        this.captureFixApplied(issue);
        this.onProgress({ phase: 'applied', details: 'Fix applied successfully' });
    }

    private captureFixApplied(issue: ScanResult): void {
        PostHogClient.captureFixApplied({
            check_id: issue.check_id || 'unknown',
            description: issue.issue || 'unknown',
            priority: issue.priority || 'unknown',
            source: issue.source,
            resource_type: issue.resourceType
        });
    }

    public async suppressIssue(issue: ScanResult, reason: string): Promise<void> {
        this.onProgress({ phase: 'suppressing', details: 'Suppressing issue' });
        await this.issueUpdater.suppress(issue, reason);
        this.captureIssueSuppressed(issue);
        this.onProgress({ phase: 'suppressed', details: 'Issue suppressed' });
    }

    private captureIssueSuppressed(issue: ScanResult): void {
        const daysOpen = this.calculateDaysOpen(issue.firstDetectedAt);
        PostHogClient.captureIssueSuppressed({
            check_id: issue.check_id || 'unknown',
            description: issue.issue || 'unknown',
            priority: issue.priority || 'unknown',
            source: issue.source,
            resource_type: issue.resourceType,
            days_open: daysOpen
        });
    }

    private calculateDaysOpen(firstDetectedAt?: string): number {
        if (!firstDetectedAt) return 0;
        const pastDate = new Date(firstDetectedAt);
        const now = new Date();
        const diffMs = now.getTime() - pastDate.getTime();
        return Math.floor(diffMs / (1000 * 60 * 60 * 24));
    }
}
