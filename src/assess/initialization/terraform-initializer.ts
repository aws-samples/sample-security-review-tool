import { TerraformDetector } from '../../shared/terraform/terraform-detector.js';
import { TerraformPlanRunner } from '../../shared/terraform/terraform-plan-runner.js';
import { ProjectContext } from '../../shared/project/project-context.js';

export class TerraformInitializer {
  private readonly detector: TerraformDetector;
  private readonly planRunner: TerraformPlanRunner;

  constructor(private readonly context: ProjectContext, private readonly onProgress: (progress: string) => void) {
    this.detector = new TerraformDetector(this.context);
    this.planRunner = new TerraformPlanRunner(this.onProgress);
  }

  public async initialize(): Promise<void> {
    const projects = await this.detector.detect();
    if (projects.length === 0) return;

    const terraformAvailable = await this.planRunner.isAvailable();
    if (!terraformAvailable) {
      this.onProgress('  ✗ Terraform CLI not found — skipping Terraform plan generation');
      return;
    }

    const failures: { name: string; path: string }[] = [];
    const totalProjects = projects.length;

    for (let i = 0; i < projects.length; i++) {
      const project = projects[i];
      const progressPrefix = totalProjects > 1 ? `[${i + 1}/${totalProjects}] ` : '';

      this.onProgress(`  › ${progressPrefix}Processing Terraform project '${project.name}'...`);
      const success = await this.planRunner.generatePlan(project);

      if (!success) {
        failures.push({ name: project.name, path: project.rootPath });
      }
    }

    if (failures.length > 0) {
      const instructions = failures
        .map(f => `  - Run 'terraform plan' in '${f.path}' to diagnose`)
        .join('\n');
      throw new Error(`Terraform plan generation failed:\n${instructions}`);
    }
  }
}
