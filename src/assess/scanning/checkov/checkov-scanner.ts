import * as path from 'path';
import * as fs from 'fs/promises';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';
import { CommandRunner } from '../../../shared/command-execution/command-runner.js';
import { ScannerToolManager } from '../../../shared/scanner-tools/scanner-tool-manager.js';
import { VenvConfig } from '../../../shared/scanner-tools/types.js';
import { ScanResult } from '../base-scanner.js';
import { ScannerUtils } from '../utils/scanner-utils.js';
import { CheckovPolicies } from './checkov_fixes.js';
import { CheckovReport, CheckovSecurityCheck } from './checkov_report.js';

export class CheckovScanner {
  private readonly cmd = new CommandRunner();
  private readonly scanToolManager: ScannerToolManager;
  private readonly venvConfig: VenvConfig;

  constructor() {
    this.scanToolManager = new ScannerToolManager();
    this.venvConfig = this.scanToolManager.getVenvConfig();
  }

  public async run(projectRootFolderPath: string, templateFilePath: string, outputFolderPath: string): Promise<string | null> {
    try {
      const scanFilePath = path.join(outputFolderPath, 'checkov-scan.json');
      const summaryFilePath = path.join(outputFolderPath, 'checkov-summary.json');

      await this.scan(templateFilePath, scanFilePath);
      await this.summarize(scanFilePath, summaryFilePath, projectRootFolderPath);

      return summaryFilePath;
    } catch (error) {
      SrtLogger.logError('Error during Checkov scan', error as Error);
      return null;
    }
  }

  public async runTerraform(projectRootFolderPath: string, tfProjectRoot: string, outputFolderPath: string): Promise<string | null> {
    try {
      const scanFilePath = path.join(outputFolderPath, 'checkov-scan.json');
      const summaryFilePath = path.join(outputFolderPath, 'checkov-summary.json');

      await this.scanTerraformDirectory(tfProjectRoot, scanFilePath);
      await this.summarize(scanFilePath, summaryFilePath, projectRootFolderPath);

      return summaryFilePath;
    } catch (error) {
      SrtLogger.logError('Error during Terraform Checkov scan', error as Error);
      return null;
    }
  }

  private async scanTerraformDirectory(tfProjectRoot: string, outputFilePath: string): Promise<void> {
    const resultPath = path.dirname(outputFilePath);
    await ScannerUtils.ensureDirectoryExists(resultPath);

    const checkovPath = this.venvConfig.checkovCmd;
    const command = `"${this.venvConfig.pythonPath}" "${checkovPath}" -d "${tfProjectRoot}" --framework terraform -o json --output-file-path "${resultPath}" --soft-fail --quiet`;

    await this.cmd.exec(command, tfProjectRoot);

    const tempOutputPath = path.join(resultPath, "results_json.json");
    await fs.rename(tempOutputPath, outputFilePath);
  }

  private async scan(templateFilePath: string, outputFilePath: string): Promise<void> {
    const resultPath = path.dirname(outputFilePath);
    await ScannerUtils.ensureDirectoryExists(resultPath);

    const checkovPath = this.venvConfig.checkovCmd;
    const command = `"${this.venvConfig.pythonPath}" "${checkovPath}" -f "${templateFilePath}" -o json --output-file-path "${resultPath}" --soft-fail --quiet`;

    await this.cmd.exec(command, path.dirname(templateFilePath));

    const tempOutputPath = path.join(resultPath, "results_json.json");
    await fs.rename(tempOutputPath, outputFilePath);
  }

  private async summarize(scanFilePath: string, summaryFilePath: string, projectRootFolderPath: string): Promise<void> {
    const json = await ScannerUtils.readJsonFile<CheckovReport>(scanFilePath);

    if (!json || !json.results || !json.results.failed_checks || !Array.isArray(json.results.failed_checks)) {
      await ScannerUtils.writeJsonFile(summaryFilePath, []);
      return;
    }

    const stackName = path.basename(path.dirname(summaryFilePath));
    const results = json.results.failed_checks.map((check: CheckovSecurityCheck) => this.mapResult(check, stackName, projectRootFolderPath));

    await ScannerUtils.writeJsonFile(summaryFilePath, results);
  }

  private mapResult(check: CheckovSecurityCheck, stackName: string, projectRootFolderPath: string): ScanResult {
    const resourceType = check.resource.split('.')[0];
    const resourceName = check.resource.split('.')[1];
    const parts = resourceType.split('::');
    let awsCdkPath: string | undefined = undefined;
    let resourceIdentifier = resourceType;

    for (const line of check.code_block) {
      const lineText = line[1];
      if (lineText.includes('aws:cdk:path')) {
        const match = lineText.match(/"aws:cdk:path":\s*"([^"]+)"/);
        if (match && match[1]) {
          awsCdkPath = match[1];
          break;
        }
      }
    }

    if (parts.length === 3 && parts[0] === 'AWS') {
      resourceIdentifier = `${parts[1]} ${parts[2]}`;
    }

    return {
      source: "Checkov",
      path: path.relative(projectRootFolderPath, check.file_abs_path) || 'unknown',
      line: check.file_line_range?.[0],
      issue: check.check_name || 'No message',
      check_id: check.check_id || 'unknown-rule',
      priority: CheckovPolicies[check.check_id]?.severity || 'LOW',
      fix: CheckovPolicies[check.check_id]?.fix,
      status: "Open",
      stack: stackName,
      resourceType: resourceIdentifier,
      resourceName: resourceName,
      cdkPath: awsCdkPath || undefined,
      isCustomResource: this.isCustomResource(awsCdkPath)
    };
  }

  private isCustomResource(cdkPath: string | undefined): boolean | undefined {
    if (!cdkPath) return false;

    const lowerCdkPath = cdkPath.toLowerCase();
    const pathSegments = lowerCdkPath.split('/');

    return lowerCdkPath.includes('custom::') ||
      pathSegments[1]?.startsWith('logretention') ||
      pathSegments[1]?.startsWith('bucketnotificationshandler') ||
      pathSegments[1]?.includes('679f53fac002430cb0da5b7982bd2287'); // CDK Custom Resource Provider ID
  }
}
