import { glob } from 'glob';
import * as path from 'path';
import { TerraformProjectConfig } from './types.js';
import { ProjectContext } from '../project/project-context.js';

export class TerraformDetector {
  constructor(private readonly context: ProjectContext) {}

  public async detect(): Promise<TerraformProjectConfig[]> {
    const tfFiles = await glob('**/*.tf', {
      ignore: this.context.getFolderIgnorePatterns(),
      cwd: this.context.getProjectRootFolderPath(),
      absolute: true,
      maxDepth: 10
    });

    if (tfFiles.length === 0) return [];

    const projectDirs = this.groupByDirectory(tfFiles);
    return this.buildProjectConfigs(projectDirs);
  }

  private groupByDirectory(tfFiles: string[]): Set<string> {
    const dirs = new Set<string>();
    for (const file of tfFiles) {
      dirs.add(path.dirname(file));
    }
    return dirs;
  }

  private buildProjectConfigs(projectDirs: Set<string>): TerraformProjectConfig[] {
    const srtOutputPath = this.context.getSrtOutputFolderPath();

    return Array.from(projectDirs).map(dir => {
      const name = path.relative(this.context.getProjectRootFolderPath(), dir) || path.basename(dir);
      const outputFolderName = name.replace(/[\\/]/g, '-') || 'terraform';

      return {
        name,
        rootPath: dir,
        planJsonPath: path.join(srtOutputPath, outputFolderName, 'plan.json'),
        outputFolderPath: path.join(srtOutputPath, outputFolderName)
      };
    });
  }
}
