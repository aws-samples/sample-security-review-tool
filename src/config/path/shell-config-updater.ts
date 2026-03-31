import fs from 'fs/promises';
import path from 'path';
import { homedir } from 'os';
import { join } from 'path';
import { OperatingSystemInfo } from './operating-system-info.js';
import { ProcessExecutor } from './process-executor.js';

export class ShellConfigUpdater {
  constructor(
    private osInfo: OperatingSystemInfo,
    private processExecutor: ProcessExecutor
  ) {}

  async updatePath(executablePath: string): Promise<{ success: boolean; needsRestart: boolean }> {
    const os = this.osInfo.getPlatform();

    if (os === 'win32') {
      return await this.updatePathWindows(executablePath);
    } else if (os === 'darwin' || os === 'linux') {
      return await this.updatePathUnix(executablePath);
    } else {
      return { success: false, needsRestart: false };
    }
  }

  getRestartInstructions(): string[] {
    const os = this.osInfo.getPlatform();

    if (os === 'win32') {
      return [
        'To use SRT from any directory, you need to:',
        '  • Close this terminal/command prompt',
        '  • Open a new terminal/command prompt'
      ];
    } else {
      return [
        'To use SRT from any directory, you need to either:',
        '  • Close and reopen your terminal, OR',
        '  • Run: source ~/.zshrc (or source ~/.bashrc)'
      ];
    }
  }

  private async updatePathWindows(newPath: string): Promise<{ success: boolean; needsRestart: boolean }> {
    try {
      const { stdout: currentPath } = await this.processExecutor.executeCommand(
        'powershell -Command "[Environment]::GetEnvironmentVariable(\'Path\', \'User\')"'
      );

      const normalizedCurrentPath = currentPath.toLowerCase().trim();
      const normalizedNewPath = newPath.toLowerCase();

      if (normalizedCurrentPath.split(';').some(p => p.trim().toLowerCase() === normalizedNewPath)) {
        return { success: true, needsRestart: false };
      }

      const escapedPath = newPath.replace(/'/g, "''");
      const psCommand = `
        $path = [Environment]::GetEnvironmentVariable('Path', 'User');
        if (-not $path.EndsWith(';')) { $path += ';' }
        [Environment]::SetEnvironmentVariable('Path', $path + '${escapedPath}', 'User');
      `.replace(/\n/g, ' ');

      await this.processExecutor.executeCommand(`powershell -Command "${psCommand}"`);

      return { success: true, needsRestart: true };
    } catch (error) {
      return { success: false, needsRestart: false };
    }
  }

  private async updatePathUnix(newPath: string): Promise<{ success: boolean; needsRestart: boolean }> {
    try {
      const shell = this.osInfo.getShell() || '';
      let configFile: string;
      let shellName: string;

      // Determine which shell config file to use
      if (shell.includes('zsh')) {
        configFile = join(homedir(), '.zshrc');
        shellName = 'zsh';
      } else if (shell.includes('bash')) {
        // Check for .bash_profile first, then .bashrc
        const bashProfile = join(homedir(), '.bash_profile');
        const bashrc = join(homedir(), '.bashrc');
        try {
          await fs.access(bashProfile);
          configFile = bashProfile;
        } catch {
          configFile = bashrc;
        }
        shellName = 'bash';
      } else if (shell.includes('fish')) {
        configFile = join(homedir(), '.config', 'fish', 'config.fish');
        shellName = 'fish';
      } else {
        configFile = join(homedir(), '.profile');
        shellName = 'sh';
      }

      let content = '';
      try {
        content = await fs.readFile(configFile, 'utf-8');
      } catch {
        if (shellName === 'fish') {
          await fs.mkdir(path.dirname(configFile), { recursive: true });
        }
      }

      const isPathActive = this.isPathInActiveExport(content, newPath, shellName);

      if (isPathActive) {
        return { success: true, needsRestart: false };
      }

      let exportLine: string;
      if (shellName === 'fish') {
        exportLine = `set -gx PATH ${newPath} $PATH`;
      } else {
        exportLine = `export PATH="${newPath}:$PATH"`;
      }

      const comment = '# Added by SRT';
      const newContent = content + `\n${comment}\n${exportLine}\n`;

      await fs.writeFile(configFile, newContent);

      return { success: true, needsRestart: true };
    } catch (error) {
      return { success: false, needsRestart: false };
    }
  }

  private isPathInActiveExport(content: string, pathToCheck: string, shellName: string): boolean {
    const lines = content.split('\n');

    for (const line of lines) {
      const trimmedLine = line.trim();

      if (trimmedLine.startsWith('#')) continue;

      if (!trimmedLine.includes(pathToCheck)) continue;

      if (shellName === 'fish') {
        if (trimmedLine.includes('set') && trimmedLine.includes('PATH')) return true;
      } else {
        if (trimmedLine.includes('export') && trimmedLine.includes('PATH')) return true;

        if (trimmedLine.startsWith('PATH=')) return true;
      }
    }

    return false;
  }
}
