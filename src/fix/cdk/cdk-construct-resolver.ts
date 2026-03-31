import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { CdkDetector } from '../../shared/cdk/cdk-detector.js';
import { CdkStackFinder } from '../../shared/cdk/cdk-stack-finder.js';
import { CdkConstructFinder } from '../../shared/cdk/cdk-construct-finder.js';
import { CdkConstructInfo, CdkProjectConfig } from '../../shared/cdk/types.js';
import { ProjectContext } from '../../shared/project/project-context.js';

export { CdkConstructInfo };

export class CdkConstructResolver {
    private readonly cdkDetector: CdkDetector;

    constructor(private readonly context: ProjectContext) {
        this.cdkDetector = new CdkDetector(this.context);
    }

    public async findConstructForIssue(cdkPath: string, templateFilePath?: string): Promise<CdkConstructInfo | null> {
        try {
            const cdkProject = await this.findCdkProjectForTemplate(templateFilePath);
            const cdkEntrypoint = cdkProject?.entrypointPath ?? await this.cdkDetector.getCdkEntrypoint();

            if (!cdkEntrypoint) {
                return null;
            }

            const cdkStackFinder = new CdkStackFinder();
            const stackClassInfo = cdkStackFinder.findStackClass(cdkEntrypoint, cdkPath.split('/')[0]);
            if (!stackClassInfo) {
                return null;
            }

            const cdkConstructFinder = new CdkConstructFinder();
            const constructResult = await cdkConstructFinder.findConstructCode(
                stackClassInfo.sourceCode,
                cdkPath,
                stackClassInfo.filePath
            );
            if (!constructResult) {
                return null;
            }

            return {
                className: stackClassInfo.className,
                filePath: constructResult.filePath,
                context: constructResult.fileContent,
                constructCode: constructResult.code,
                lineNumber: constructResult.lineNumber
            };
        } catch (error) {
            SrtLogger.logError('Error finding CDK construct for issue', error as Error, { projectRootFolderPath: this.context.getProjectRootFolderPath(), cdkPath });
            return null;
        }
    }

    private async findCdkProjectForTemplate(templateFilePath?: string): Promise<CdkProjectConfig | null> {
        if (!templateFilePath) return null;

        const cdkProjects = await this.cdkDetector.getAllCdkProjects();
        if (cdkProjects.length <= 1) {
            return cdkProjects[0] ?? null;
        }

        for (const project of cdkProjects) {
            if (templateFilePath.startsWith(project.outputPath)) {
                return project;
            }
        }

        return cdkProjects[0] ?? null;
    }
}
