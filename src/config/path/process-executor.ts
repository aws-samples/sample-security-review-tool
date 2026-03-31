import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export class ProcessExecutor {
  async executeCommand(command: string): Promise<{ stdout: string; stderr: string }> {
    return await execAsync(command);
  }

  checkPathMembership(executablePath: string, systemPath: string): boolean {
    const pathSeparator = process.platform === 'win32' ? ';' : ':';
    const pathDirs = systemPath.split(pathSeparator);

    const normalizedExecPath = process.platform === 'win32' ? executablePath.toLowerCase() : executablePath;
    const normalizedPathDirs = pathDirs.map(dir =>
      process.platform === 'win32' ? dir.toLowerCase() : dir
    );

    return normalizedPathDirs.some(dir => {
      const normalizedDir = dir.replace(/[/\\]$/, '');
      const normalizedExec = normalizedExecPath.replace(/[/\\]$/, '');
      return normalizedDir === normalizedExec;
    });
  }
}
