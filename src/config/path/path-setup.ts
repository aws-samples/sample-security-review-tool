import { OperatingSystemInfo } from './operating-system-info.js';
import { ProcessExecutor } from './process-executor.js';
import { ShellConfigUpdater } from './shell-config-updater.js';

export interface PathCheckResult {
  isInPath: boolean;
  executablePath: string;
}

export interface PathUpdateResult {
  success: boolean;
  needsRestart: boolean;
}

export class PathInstallationSetup {
  private osInfo = new OperatingSystemInfo();
  private processExecutor = new ProcessExecutor();
  private shellConfigUpdater = new ShellConfigUpdater(this.osInfo, this.processExecutor);

  constructor() { }

  checkPath(): PathCheckResult {
    const executableDir = this.osInfo.getExecutablePath();
    const systemPath = this.osInfo.getEnvironmentPath();
    const isInPath = this.processExecutor.checkPathMembership(executableDir, systemPath);

    return {
      isInPath,
      executablePath: executableDir
    };
  }

  async updatePath(): Promise<PathUpdateResult> {
    const executableDir = this.osInfo.getExecutablePath();
    return await this.shellConfigUpdater.updatePath(executableDir);
  }

  getRestartInstructions(): string[] {
    return this.shellConfigUpdater.getRestartInstructions();
  }
}
