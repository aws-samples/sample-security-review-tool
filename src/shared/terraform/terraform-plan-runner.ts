import * as path from 'path';
import * as fs from 'fs/promises';
import { CommandRunner } from '../command-execution/command-runner.js';
import { SrtLogger } from '../logging/srt-logger.js';
import { TerraformProjectConfig } from './types.js';

export class TerraformPlanRunner {
  private readonly cmd = new CommandRunner();

  constructor(private readonly onProgress: (msg: string) => void = () => {}) {}

  public async isAvailable(): Promise<boolean> {
    try {
      await this.cmd.exec('terraform version', process.cwd(), true);
      return true;
    } catch {
      return false;
    }
  }

  public async generatePlan(project: TerraformProjectConfig): Promise<boolean> {
    try {
      await fs.mkdir(path.dirname(project.planJsonPath), { recursive: true });

      this.onProgress(`  › Initializing Terraform for ${project.name}...`);
      await this.cmd.exec(
        'terraform init -backend=false -input=false',
        project.rootPath,
        true
      );

      this.onProgress(`  › Generating Terraform plan for ${project.name}...`);
      const planFilePath = path.join(project.outputFolderPath, 'tfplan');
      await this.cmd.exec(
        `terraform plan -out="${planFilePath}" -input=false`,
        project.rootPath,
        true
      );

      this.onProgress(`  › Exporting Terraform plan JSON for ${project.name}...`);
      const planJson = await this.cmd.exec(
        `terraform show -json "${planFilePath}"`,
        project.rootPath,
        true
      );

      await fs.writeFile(project.planJsonPath, planJson, 'utf-8');

      this.onProgress(`  ✔ Generated Terraform plan for ${project.name}`);
      return true;
    } catch (error) {
      this.onProgress(`  ✗ Failed to generate Terraform plan for ${project.name}`);
      SrtLogger.logError(`Error generating Terraform plan for ${project.name}`, error as Error);
      return false;
    }
  }
}
