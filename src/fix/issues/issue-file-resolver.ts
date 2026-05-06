import * as path from 'path';
import { ScanResult } from '../../assess/scanning/types.js';
import { ProjectContext } from '../../shared/project/project-context.js';
import { CdkConstructResolver } from '../cdk/cdk-construct-resolver.js';
import { TerraformSourceResolver } from '../agent/prompts/terraform-source-resolver.js';

export class IssueFileResolver {
    private readonly cdkConstructResolver: CdkConstructResolver;

    constructor(private context: ProjectContext) {
        this.cdkConstructResolver = new CdkConstructResolver(context);
    }

    public async getCodeFilePath(issue: ScanResult): Promise<string | null> {
        if (!issue.path || !issue.issue || !issue.fix) return null;

        if (issue.source === 'terraform-matrix') {
            const resolver = new TerraformSourceResolver(this.context);
            const source = await resolver.resolve(issue);
            return source?.path ?? null;
        }

        const isCloudFormationTemplate = await this.context.isCloudFormationTemplate(
            path.join(this.context.getProjectRootFolderPath(), issue.path)
        );

        const isCdkProject = await this.context.isCdkProject();

        if (isCloudFormationTemplate && isCdkProject && issue.cdkPath) {
            const templateFilePath = path.join(this.context.getProjectRootFolderPath(), issue.path);
            const cdkConstruct = await this.cdkConstructResolver.findConstructForIssue(issue.cdkPath, templateFilePath);
            return cdkConstruct?.filePath || null;
        }

        return issue.path;
    }
}
