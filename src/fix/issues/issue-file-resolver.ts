import * as path from 'path';
import { ScanResult } from '../../assess/scanning/types.js';
import { ProjectContext } from '../../shared/project/project-context.js';
import { CdkConstructResolver } from '../cdk/cdk-construct-resolver.js';

export class IssueFileResolver {
    private readonly cdkConstructResolver: CdkConstructResolver;

    constructor(private context: ProjectContext) {
        this.cdkConstructResolver = new CdkConstructResolver(context);
    }

    public async getCodeFilePath(issue: ScanResult): Promise<string | null> {
        if (!issue.path || !issue.issue || !issue.fix) return null;

        const isCloudFormationTemplate = await this.context.isCloudFormationTemplate(
            path.join(this.context.getProjectRootFolderPath(), issue.path)
        );

        const isCdkProject = await this.context.isCdkProject();

        // For CDK projects with CloudFormation templates, find the corresponding CDK construct file
        if (isCloudFormationTemplate && isCdkProject && issue.cdkPath) {
            const templateFilePath = path.join(this.context.getProjectRootFolderPath(), issue.path);
            const cdkConstruct = await this.cdkConstructResolver.findConstructForIssue(issue.cdkPath, templateFilePath);
            return cdkConstruct?.filePath || null;
        }

        // For non-CDK CloudFormation projects or other file types, return the original file path
        return issue.path;
    }
}
