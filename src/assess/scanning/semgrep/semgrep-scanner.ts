import * as path from 'path';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';
import { CommandRunner } from '../../../shared/command-execution/command-runner.js';
import { ScannerToolManager } from '../../../shared/scanner-tools/scanner-tool-manager.js';
import { VenvConfig } from '../../../shared/scanner-tools/types.js';
import { BaseScanner, ScanResult } from '../base-scanner.js';
import { ScannerUtils } from '../utils/scanner-utils.js';
import { SemgrepFixes } from './semgrep-fixes.js';
import { ProjectContext } from '../../../shared/project/project-context.js';

export class SemgrepScanner extends BaseScanner {
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
      const semgrepPath = this.venvConfig.semgrepCmd;
      const excludePaths = this.context.getIgnoredDirectoryNames();

      const excludeArgs = excludePaths.map(p => `--exclude "${p}"`).join(' ');
      const finalCommand = `"${this.venvConfig.pythonPath}" "${semgrepPath}" scan --config=auto ${excludeArgs} --json --output="${outputFilePath}" "${projectRootFolderPath}"`;

      await this.cmd.exec(finalCommand, projectRootFolderPath);
    } catch (error) {
      SrtLogger.logError('Error during Semgrep scan', error as Error);
      throw error;
    }
  }

  public async summarize(scanFilePath: string, summaryFilePath: string, projectRootFolderPath: string = ''): Promise<void> {
    try {
      const json = await ScannerUtils.readJsonFile<any>(scanFilePath);
      if (!json || !json.results || !Array.isArray(json.results)) {
        await ScannerUtils.writeJsonFile(summaryFilePath, []);
        return;
      }

      const mappedResults = json.results.map((result: any) => {
        const filePath = result.path || 'unknown';

        if (filePath.includes('-converted.py')) {
          const originalNotebookPath = filePath.replace('-converted.py', '.ipynb');
          return this.mapResult(projectRootFolderPath, result, originalNotebookPath);
        } else {
          return this.mapResult(projectRootFolderPath, result);
        }
      });

      const filteredResults = ScannerUtils.filterResults(mappedResults, this.context.getIgnoredDirectoryNames());

      await ScannerUtils.writeJsonFile(summaryFilePath, filteredResults);
    } catch (error) {
      SrtLogger.logError('Error processing Semgrep scan results', error as Error);
      await ScannerUtils.writeJsonFile(summaryFilePath, []);
    }
  }

  private mapResult(projectRootFolderPath: string, result: any, customPath?: string): ScanResult {
    const relativePath = customPath ? path.relative(projectRootFolderPath, customPath) : path.relative(projectRootFolderPath, result.path);
    const checkId = result.check_id || result.rule_id || 'unknown-rule';

    return {
      source: 'Semgrep',
      path: relativePath,
      line: result.start?.line,
      issue: result.extra?.message || result.message || 'No message',
      fix: SemgrepFixes[checkId],
      check_id: checkId,
      priority: result.extra?.metadata?.impact || 'Unknown',
      references: result.extra?.metadata?.references?.join(' | ') || '',
      status: 'Open'
    };
  }
}
