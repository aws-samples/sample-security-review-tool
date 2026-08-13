import { CommandRunner } from '../command-execution/command-runner.js';
import { SrtLogger } from '../logging/srt-logger.js';
import { TerraformProjectConfig } from './types.js';

export class TerraformModuleLoader {
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

  public async loadModules(project: TerraformProjectConfig): Promise<boolean> {
    try {
      await this.cmd.exec('terraform get', project.rootPath, true);
      this.onProgress(`  ✔ Loaded Terraform modules for ${project.name}`);
      return true;
    } catch (error) {
      this.onProgress(`  ! Could not load Terraform modules for ${project.name} — scanning root module only`);
      SrtLogger.logError(`Error loading Terraform modules for ${project.name}`, error as Error);
      return false;
    }
  }
}
