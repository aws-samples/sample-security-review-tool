import { CdkDetector } from '../../shared/cdk/cdk-detector.js';
import { CdkToolManager } from '../../shared/cdk/cdk-tool-manager.js';
import { CdkSynthesizer } from '../../shared/cdk/cdk-synthesizer.js';
import { ProjectContext } from '../../shared/project/project-context.js';

export class CdkInitializer {
    private readonly cdkDetector: CdkDetector;
    private readonly cdkToolManager: CdkToolManager;
    private readonly cdkSynthesizer: CdkSynthesizer;

    constructor(private readonly context: ProjectContext, private readonly onProgress: (progress: string) => void) {
        this.cdkDetector = new CdkDetector(this.context);
        this.cdkToolManager = new CdkToolManager();
        this.cdkSynthesizer = new CdkSynthesizer(this.context);
    }

    public async initialize(): Promise<void> {
        if (this.context.hasCdkOutOverrides()) {
            const count = this.context.getCdkOutOverridePaths().length;
            const plural = count > 1 ? 'directories' : 'directory';
            this.onProgress(`  ✔ Using ${count} pre-existing CDK output ${plural}`);
            return;
        }

        const cdkProjects = await this.cdkDetector.getAllCdkProjects();
        if (cdkProjects.length === 0) {
            return;
        }

        await this.ensureCdkToolInstalled(cdkProjects[0].rootPath);

        const failures: { name: string; path: string }[] = [];
        const totalProjects = cdkProjects.length;

        for (let i = 0; i < cdkProjects.length; i++) {
            const project = cdkProjects[i];
            const progressPrefix = totalProjects > 1 ? `[${i + 1}/${totalProjects}] ` : '';

            this.onProgress(`  › ${progressPrefix}Synthesizing CDK project '${project.name}'...`);
            const result = await this.cdkSynthesizer.synthesizeProject(project);

            if (result.success) {
                this.onProgress(`  ✔ ${progressPrefix}Synthesized CDK project '${project.name}'`);
            } else {
                this.onProgress(`  ✗ ${progressPrefix}Failed to synthesize '${project.name}'`);
                failures.push({ name: project.name, path: project.rootPath });
            }
        }

        if (failures.length > 0) {
            const instructions = failures
                .map(f => `  - Run 'cdk synth' in '${f.path}' to diagnose`)
                .join('\n');
            throw new Error(`CDK synthesis failed:\n${instructions}`);
        }
    }

    private async ensureCdkToolInstalled(workingDirectory: string): Promise<void> {
        const toolInstalled = await this.cdkToolManager.isCdkInstalled();
        if (!toolInstalled) {
            await this.cdkToolManager.installCdk(workingDirectory);
        }
    }
}
