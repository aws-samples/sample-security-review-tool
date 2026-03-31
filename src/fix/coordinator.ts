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
        const ignorePatternService = await IgnorePatternService.create(projectRootFolderPath);
        const context = new ProjectContext(projectRootFolderPath, ignorePatternService);
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
        return fix;
    }

    public async applyFix(issue: ScanResult, fix: Fix): Promise<void> {
        this.onProgress({ phase: 'applying', details: 'Applying fix to code' });
        await this.codeApplicator.applyFix(issue, fix);
        this.onProgress({ phase: 'applied', details: 'Fix applied successfully' });
    }

    public async suppressIssue(issue: ScanResult, reason: string): Promise<void> {
        this.onProgress({ phase: 'suppressing', details: 'Suppressing issue' });
        await this.issueUpdater.suppress(issue, reason);
        this.onProgress({ phase: 'suppressed', details: 'Issue suppressed' });
    }
}
