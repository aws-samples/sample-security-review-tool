import * as path from 'path';
import * as fs from 'fs/promises';
import { BaseScanner, ScanResult } from '../base-scanner.js';
import { ScannerUtils } from '../utils/scanner-utils.js';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';
import { CommandRunner } from '../../../shared/command-execution/command-runner.js';
import { ScannerToolManager } from '../../../shared/scanner-tools/scanner-tool-manager.js';
import { VenvConfig } from '../../../shared/scanner-tools/types.js';
import { ProjectContext } from '../../../shared/project/project-context.js';
import { BanditFixes } from './bandit-fixes.js';

export class BanditScanner extends BaseScanner {
  private readonly cmd = new CommandRunner();
  private readonly scanToolManager: ScannerToolManager;
  private readonly venvConfig: VenvConfig;
  private readonly priorityOverrides: Record<string, string> = {
    'B105': 'High',
    'B106': 'High'
  };

  constructor(context: ProjectContext) {
    super(context);

    this.scanToolManager = new ScannerToolManager();
    this.venvConfig = this.scanToolManager.getVenvConfig();
  }

  public async scan(_projectRootFolderPath: string, outputFilePath: string): Promise<void> {
    try {
      const excludeDirs = this.getExcludeDirs();

      const excludePaths = excludeDirs.map(dir => {
        if (process.platform === 'win32') {
          return `.\\${dir}`;
        }
        return `./${dir}`;
      });

      const excludeParam = excludePaths.length > 0 ? `--exclude "${excludePaths.join(',')}"` : '';

      const suppressStderr = process.platform === 'win32' ? '2>NUL' : '2>/dev/null';
      const banditPath = this.venvConfig.banditCmd;

      const finalCommand = `"${this.venvConfig.pythonPath}" "${banditPath}" ${excludeParam} -r . -f json -o "${outputFilePath}" -q --exit-zero ${suppressStderr}`;
      await this.cmd.exec(finalCommand, this.context.getProjectRootFolderPath());
    } catch (error) {
      SrtLogger.logError('Error during Bandit scan', error as Error);
      throw error;
    }
  }

  public async summarize(scanFilePath: string, summaryFilePath: string): Promise<void> {
    try {
      const json = await ScannerUtils.readJsonFile<any>(scanFilePath);
      if (!json || !json.results || !Array.isArray(json.results)) {
        await ScannerUtils.writeJsonFile(summaryFilePath, []);
        return;
      }

      const mappedResults = json.results.map((result: any) => {
        const filename = result.filename || 'unknown';
        if (filename.includes('-converted.py')) {
          const originalNotebookPath = filename.replace('-converted.py', '.ipynb');
          return this.mapResult(result, path.normalize(originalNotebookPath));
        } else {
          return this.mapResult(result);
        }
      });

      const filteredResults = ScannerUtils.filterResults(mappedResults, this.context.getIgnoredDirectoryNames());
      await ScannerUtils.writeJsonFile(summaryFilePath, filteredResults);
    } catch (error) {
      SrtLogger.logError('Error processing Bandit scan results', error as Error);
      await ScannerUtils.writeJsonFile(summaryFilePath, []);
    }
  }

  private mapResult(result: any, customPath?: string): ScanResult {
    return {
      source: 'Bandit',
      path: customPath || path.normalize(result.filename) || 'unknown',
      line: result.line_number,
      issue: result.issue_text || 'No message',
      fix: BanditFixes[result.test_id],
      check_id: result.test_id || 'unknown-rule',
      priority: this.priorityOverrides[result.test_id] || ScannerUtils.mapSeverity(result.issue_severity),
      references: result.more_info || '',
      status: 'Open'
    };
  }

  public async convertNotebooks(notebookFiles: string[], venvConfig: VenvConfig, onProgress: (msg: string) => void = () => {}): Promise<string[]> {
    onProgress(`  › Exporting code from ${notebookFiles.length} notebook(s) for analysis...`);

    const conversionPromises = notebookFiles.map(async (notebookFile) => {
      const filename = path.basename(notebookFile);
      onProgress(`    › exporting ${filename}...`);

      try {
        const notebookDir = path.dirname(notebookFile);
        const baseName = path.basename(notebookFile, '.ipynb');
        const outputName = `${baseName}-converted`;
        const pythonFile = path.join(notebookDir, `${outputName}.py`);

        const nbconvertCmd = `"${venvConfig.pythonPath}" "${venvConfig.jupyterlabCmd}" nbconvert --log-level WARN --to script "${notebookFile}" --output "${outputName}"`;

        await this.cmd.exec(nbconvertCmd, notebookDir);

        try {
          await fs.access(pythonFile);
          return pythonFile;
        } catch {
          return null;
        }
      } catch {
        return null;
      }
    });

    const results = await Promise.allSettled(conversionPromises);
    const convertedFiles = results
      .filter((r): r is PromiseFulfilledResult<string> => r.status === 'fulfilled' && r.value !== null)
      .map(r => r.value);

    onProgress(`  ✔ Exported ${convertedFiles.length}/${notebookFiles.length} notebook(s)`);

    return convertedFiles;
  }

  private getExcludeDirs(): string[] {
    return this.context.getIgnoredDirectoryNames();
  }
}
