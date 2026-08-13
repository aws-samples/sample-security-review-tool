import { TerraformDetector } from '../../shared/terraform/terraform-detector.js';
import { TerraformModuleLoader } from '../../shared/terraform/terraform-module-loader.js';
import { ProjectContext } from '../../shared/project/project-context.js';

export class TerraformInitializer {
  private readonly detector: TerraformDetector;
  private readonly moduleLoader: TerraformModuleLoader;

  constructor(private readonly context: ProjectContext, private readonly onProgress: (progress: string) => void) {
    this.detector = new TerraformDetector(this.context);
    this.moduleLoader = new TerraformModuleLoader(this.onProgress);
  }

  public async initialize(): Promise<void> {
    const projects = await this.detector.detect();
    if (projects.length === 0) return;

    if (!await this.moduleLoader.isAvailable()) {
      this.onProgress('  ! Terraform CLI not found — scanning Terraform root modules only');
      return;
    }

    for (const [index, project] of projects.entries()) {
      const progressPrefix = projects.length > 1 ? `[${index + 1}/${projects.length}] ` : '';
      this.onProgress(`  › ${progressPrefix}Processing Terraform project '${project.name}'...`);
      await this.moduleLoader.loadModules(project);
    }
  }
}
