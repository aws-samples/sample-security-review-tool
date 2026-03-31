import { platform } from 'os';
import { homedir } from 'os';
import { join } from 'path';
import { AppPaths } from '../../shared/app-config/app-paths.js';

export class OperatingSystemInfo {
  public getPlatform(): NodeJS.Platform {
    return platform();
  }

  public getShell(): string | undefined {
    return process.env.SHELL;
  }

  public getExecutablePath(): string {
    return AppPaths.getAppDir();
  }

  public getEnvironmentPath(): string {
    return process.env.PATH || '';
  }

  public getShellConfigFiles(): string[] {
    const shell = this.getShell() || '';
    const os = this.getPlatform();

    if (os === 'win32') {
      return [];
    }

    if (shell.includes('zsh')) {
      return [join(homedir(), '.zshrc')];
    } else if (shell.includes('bash')) {
      return [join(homedir(), '.bash_profile'), join(homedir(), '.bashrc')];
    } else if (shell.includes('fish')) {
      return [join(homedir(), '.config', 'fish', 'config.fish')];
    } else {
      return [join(homedir(), '.profile')];
    }
  }
}
