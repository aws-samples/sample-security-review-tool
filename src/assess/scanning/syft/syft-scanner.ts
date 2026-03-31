import { SrtLogger } from '../../../shared/logging/srt-logger.js';
import { CommandRunner } from '../../../shared/command-execution/command-runner.js';
import { ScannerToolManager } from '../../../shared/scanner-tools/scanner-tool-manager.js';
import { VenvConfig } from '../../../shared/scanner-tools/types.js';
import { BaseScanner } from '../base-scanner.js';
import { ScannerUtils } from '../utils/scanner-utils.js';
import { ProjectContext } from '../../../shared/project/project-context.js';

export class SyftScanner extends BaseScanner {
  private static readonly MAX_LICENSE_LENGTH = 32760;
  private readonly cmd = new CommandRunner();
  private readonly scanToolManager: ScannerToolManager;
  private readonly venvConfig: VenvConfig;

  constructor(context: ProjectContext) {
    super(context);
    this.scanToolManager = new ScannerToolManager();
    this.venvConfig = this.scanToolManager.getVenvConfig();
  }

  public async scan(projectRootFolderPath: string, outputFilePath: string): Promise<void> {
    try {
      const syftPath = this.venvConfig.syftCmd;
      const excludeArgs = this.context.getIgnoredDirectoryNames().map(dir => `--exclude "**/${dir}/**"`).join(' ');
      const finalCommand = `"${this.venvConfig.pythonPath}" "${syftPath}" "${projectRootFolderPath}" ${excludeArgs} -o json="${outputFilePath}"`;

      await this.cmd.exec(finalCommand, projectRootFolderPath);
    } catch (error) {
      SrtLogger.logError('Error during Syft scan', error as Error);
      throw error;
    }
  }

  public async summarize(scanFilePath: string, summaryFilePath: string): Promise<void> {
    try {
      const json = await ScannerUtils.readJsonFile<any>(scanFilePath);
      if (!json || !json.artifacts || !Array.isArray(json.artifacts)) {
        await ScannerUtils.writeJsonFile(summaryFilePath, []);
        return;
      }

      const packagesByType: Record<string, any[]> = {};

      json.artifacts.forEach((artifact: any) => {
        if (artifact.type === 'system-package') return;

        const type = artifact.type || 'unknown';
        if (!packagesByType[type]) {
          packagesByType[type] = [];
        }

        packagesByType[type].push({
          name: artifact.name,
          version: artifact.version || 'unknown',
          license: (() => {
            const licenseStr = artifact.licenses?.map((l: any) => l.spdxId || l.value || 'unknown').join(', ') || 'unknown';
            return licenseStr.slice(0, SyftScanner.MAX_LICENSE_LENGTH);
          })(),
          path: artifact.locations && artifact.locations.length > 0 ? artifact.locations[0].path : 'unknown'
        });
      });

      const summary = {
        summary: {
          totalPackages: json.artifacts.length,
          packagesByType: Object.entries(packagesByType).map(([type, packages]) => ({
            type,
            count: packages.length
          }))
        },
        packages: Object.entries(packagesByType).map(([type, packages]) => ({
          type,
          packages: packages.sort((a, b) => a.name.localeCompare(b.name))
        }))
      };

      await ScannerUtils.writeJsonFile(summaryFilePath, [summary]);
    } catch (error) {
      SrtLogger.logError('Error processing Syft scan results', error as Error);
      await ScannerUtils.writeJsonFile(summaryFilePath, []);
    }
  }

  protected async countFindings(summaryFilePath: string): Promise<number> {
    // Syft is a package inventory tool, not a security scanner so no findings
    return 0;
  }
}
