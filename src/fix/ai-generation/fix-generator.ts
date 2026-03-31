import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { ScanResult } from '../../assess/scanning/types.js';
import { ProjectContext } from '../../shared/project/project-context.js';
import { CdkConstructResolver } from '../cdk/cdk-construct-resolver.js';
import { CdkFixPrompter } from './cdk-fix-prompter.js';
import { CfnFixPrompter } from './cfn-fix-prompter.js';
import { CodeFixPrompter } from './code-fix-prompter.js';
import { Fix } from '../types.js';
import * as path from 'path';

export class FixGenerator {
    private readonly cdkFixPrompter = new CdkFixPrompter();
    private readonly cfnFixPrompter = new CfnFixPrompter();
    private readonly codeFixPrompter = new CodeFixPrompter();
    private readonly cdkConstructResolver: CdkConstructResolver;

    constructor(private readonly context: ProjectContext) {
        this.cdkConstructResolver = new CdkConstructResolver(context);
    }

    public async generateFix(issue: ScanResult): Promise<Fix | null> {
        try {
            if (!issue.path || !issue.issue || !issue.fix) {
                return null;
            }

            // Handle Bandit and Semgrep issues (code-level security findings)
            if (issue.source === 'Bandit' || issue.source === 'Semgrep') {
                return await this.codeFixPrompter.generateFix(
                    this.context.getProjectRootFolderPath(),
                    issue
                );
            }

            const isCloudFormationTemplate = await this.context.isCloudFormationTemplate(
                path.join(this.context.getProjectRootFolderPath(), issue.path)
            );

            const isCdkProject = await this.context.isCdkProject();

            // Handle CDK projects
            if (isCloudFormationTemplate && isCdkProject && issue.cdkPath) {
                const templateFilePath = path.join(this.context.getProjectRootFolderPath(), issue.path);
                const cdkConstruct = await this.cdkConstructResolver.findConstructForIssue(issue.cdkPath, templateFilePath);

                if (cdkConstruct) {
                    return await this.cdkFixPrompter.generateFix(cdkConstruct, issue);
                }
            }

            // Handle non-CDK CloudFormation projects
            if (isCloudFormationTemplate && !isCdkProject && issue.resourceName) {
                return await this.cfnFixPrompter.generateFix(this.context.getProjectRootFolderPath(), issue);
            }

            return null;

        } catch (error) {
            SrtLogger.logError('Fix generation failed', error as Error, { checkId: issue.check_id, path: issue.path });
            return null;
        }
    }
}
