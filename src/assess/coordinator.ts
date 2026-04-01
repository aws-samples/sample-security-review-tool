import { SrtLogger } from '../shared/logging/srt-logger.js';
import { ui } from '../shared/ui.js';
import type { Ora } from 'ora';
import { CodeScanResult, TemplateResult } from './types.js';
import { InitializationCoordinator } from './initialization/coordinator.js';
import { ProjectContext } from '../shared/project/project-context.js';
import { LicenseComplianceCoordinator } from './licensing/coordinator.js';
import { ScannerCoordinator } from './scanning/scanner-coordinator.js';
import { TemplateCoordinator as TemplateCoordinator } from './template-processing/coordinator.js';
import { ReportGenerator } from './reporting/report-generator.js';
import { ProjectSettingsManager } from '../shared/project/project-settings-manager.js';
import { ProjectSummarizer } from './summarization/project-summarizer.js';
import { IgnorePatternService } from '../shared/file-system/ignore-pattern-service.js';
import { PostHogClient } from '../shared/analytics/posthog-client.js';
import { AppConfig } from '../shared/app-config/app-config.js';
import { AssessmentSummary } from './reporting/types.js';

export class AssessCoordinator {
    private context!: ProjectContext;
    private projectSettingsManager!: ProjectSettingsManager;

    constructor(
        private readonly projectRootFolderPath: string,
        private readonly onProgress: (progress: string) => void = () => { },
        private readonly cdkOutPaths?: string[]
    ) {}

    public async assess(license: string, updateLicenses: boolean, generateDiagrams: boolean, generateThreatModels: boolean, generateXlsx: boolean = false): Promise<void> {
        const ignorePatternService = await IgnorePatternService.create(this.projectRootFolderPath);
        this.context = new ProjectContext(this.projectRootFolderPath, ignorePatternService, this.cdkOutPaths);
        this.projectSettingsManager = new ProjectSettingsManager(this.context);

        const projectId = await this.projectSettingsManager.ensureProjectId();
        const installationId = AppConfig.getInstallationId();
        if (installationId && AppConfig.isTelemetryEnabled()) {
            PostHogClient.initialize(installationId, projectId);
        }

        try {
            await this.initializeProject();
            await this.checkLicenseCompliance(license, updateLicenses);
            const codeScanResult = await this.runCodeScanners();
            const templateResults = await this.processTemplates(generateDiagrams, generateThreatModels);
            const projectSummary = await this.generateProjectSummary(templateResults);

            const assessmentSummary = await this.generateReports(
                codeScanResult,
                templateResults,
                generateXlsx,
                projectSummary
            );

            if (assessmentSummary) {
                this.captureAssessmentCompleted(assessmentSummary);
            }

            await this.projectSettingsManager.updateLastScanDate();
        } catch (error) {
            SrtLogger.logError('Assessment failed', error as Error, { projectRootFolderPath: this.context.getProjectRootFolderPath(), license });
            throw error;
        }
    }

    private spinProgress(spin: Ora, msg: string): void {
        // Strip leading whitespace/symbols for clean spinner text
        const clean = msg.replace(/^\s*[›✔✗·]\s*/, '');
        if (clean) spin.text = clean;
    }

    private async initializeProject(): Promise<void> {
        const spin = ui.spinner('Initializing project...').start();
        const initCoordinator = new InitializationCoordinator(this.context, (msg) => this.spinProgress(spin, msg));
        await initCoordinator.initialize();
        spin.succeed('Project initialized');
    }

    private async checkLicenseCompliance(license: string, updateLicenses: boolean): Promise<void> {
        if(!updateLicenses) return;
        
        const spin = ui.spinner('Validating license compliance...').start();
        const licenseCoordinator = new LicenseComplianceCoordinator(this.context, license);
        await licenseCoordinator.execute();
        spin.succeed('Validated license compliance');
    }

    private async runCodeScanners(): Promise<CodeScanResult> {
        const spin = ui.spinner('Running security scans...').start();
        const scanCoordinator = new ScannerCoordinator(this.context, (msg) => this.spinProgress(spin, msg));
        const codeScanResult = await scanCoordinator.scanCode();
        spin.succeed('Completed security scans');

        return codeScanResult;
    }

    private async processTemplates(generateDiagrams: boolean, generateThreatModels: boolean): Promise<TemplateResult[]> {
        const spin = ui.spinner('Processing CloudFormation templates...').start();
        const templateCoordinator = new TemplateCoordinator(this.context, generateDiagrams, generateThreatModels, (msg) => this.spinProgress(spin, msg));
        const templateResults = await templateCoordinator.processTemplates();
        spin.succeed('Processed CloudFormation templates');

        return templateResults;
    }

    private async generateProjectSummary(templateResults: TemplateResult[]): Promise<string | null> {
        const spin = ui.spinner('Generating assessment summary...').start();
        const summarizer = new ProjectSummarizer(this.context, (msg) => this.spinProgress(spin, msg));
        const result = await summarizer.summarize(templateResults);
        spin.succeed('Generated assessment summary');

        return result;
    }

    private async generateReports(
        codeScanResult: CodeScanResult,
        templateResults: TemplateResult[],
        generateXlsx: boolean,
        projectSummary: string | null
    ): Promise<AssessmentSummary | null> {
        const spin = ui.spinner('Creating SRT report...').start();
        const reportGenerator = new ReportGenerator(this.context, (msg) => this.spinProgress(spin, msg));
        const summary = await reportGenerator.generateReports({
            codeScanResult,
            templateResults,
            generateXlsx,
            projectSummary
        });
        spin.succeed('Created SRT report');
        return summary;
    }

    private captureAssessmentCompleted(summary: AssessmentSummary): void {
        PostHogClient.captureAssessmentCompleted({
            total_issues: summary.totalIssues,
            new_issues: summary.newIssues,
            resolved_issues: summary.resolvedIssues,
            reopened_issues: summary.reopenedIssues,
            high_priority: summary.highPriority,
            medium_priority: summary.mediumPriority,
            low_priority: summary.lowPriority,
            by_source: summary.bySource
        });
    }
}
