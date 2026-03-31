import * as fs from 'fs/promises';
import * as path from 'path';
import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { BaseScanner } from './base-scanner.js';
import { BanditScanner } from './bandit/bandit-scanner.js';
import { SemgrepScanner } from './semgrep/semgrep-scanner.js';
import { SyftScanner } from './syft/syft-scanner.js';
import { VenvConfig } from '../../shared/scanner-tools/types.js';
import { ProjectContext } from '../../shared/project/project-context.js';
import { CodeScanResult } from '../types.js';

export interface ScanCoordinatorOptions {
  projectRootFolderPath: string;
  srtOutputFolderPath: string;
  srtApplicationFolderPath: string;
  isPythonProject: boolean;
  hasJupyterNotebooks: boolean;
}

export class ScannerCoordinator {
  private readonly scanners: Map<string, BaseScanner> = new Map();

  constructor(private readonly context: ProjectContext, private readonly onProgress: (progress: string) => void = () => { }) {
    this.scanners.set('bandit', new BanditScanner(context));
    this.scanners.set('semgrep', new SemgrepScanner(context));
    this.scanners.set('syft', new SyftScanner(context));
  }

  public async scanCode(): Promise<CodeScanResult> {
    try {
      let convertedFiles: string[] = [];

      const runBandit = await this.context.isPythonProject() || await this.context.hasJupyterNotebooks();

      if (runBandit) {
        const banditScanner = this.scanners.get('bandit') as BanditScanner;
        const notebookFiles = await this.context.findJupyterNotebooks();
        if (notebookFiles.length > 0) {
          const venvConfig = (banditScanner as any).venvConfig as VenvConfig;
          convertedFiles = await banditScanner.convertNotebooks(notebookFiles, venvConfig, this.onProgress);
        }
      }

      const scanPromises: Promise<void>[] = [
        this.runScanner('semgrep'),
        this.runScanner('syft')
      ];

      if (runBandit) {
        scanPromises.push(this.runScanner('bandit'));
      }

      await Promise.allSettled(scanPromises);

      for (const file of convertedFiles) {
        await fs.unlink(file).catch(() => { });
      }

      return {
        semgrepSummaryPath: path.join(this.context.getSrtOutputFolderPath(), 'semgrep-summary.json'),
        banditSummaryPath: runBandit ? path.join(this.context.getSrtOutputFolderPath(), 'bandit-summary.json') : null,
        syftSummaryPath: path.join(this.context.getSrtOutputFolderPath(), 'syft-summary.json')
      };
    } catch (error) {
      SrtLogger.logError('Code scan failed', error as Error, { projectRootFolderPath: this.context.getProjectRootFolderPath() });
      throw error;
    }
  }

  private async runScanner(tool: string): Promise<void> {
    const scanner = this.scanners.get(tool);
    if (!scanner) return;

    this.onProgress(`  › Starting ${tool} scan...`);
    try {
      await scanner.execute(this.context.getProjectRootFolderPath(), this.context.getSrtOutputFolderPath(), tool);
      this.onProgress(`  ✔ Completed ${tool} scan`);
    } catch {
      this.onProgress(`  ✗ Failed to perform ${tool} scan`);
    }
  }
}
