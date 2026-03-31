import * as path from 'path';
import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { ScanResult, Scanner } from './types.js';
import { ProjectContext } from '../../shared/project/project-context.js';

// Re-export ScanResult so it can be imported by rule files
export { ScanResult };

export abstract class BaseScanner implements Scanner {
    abstract scan(projectRootFolderPath: string, outputFilePath: string): Promise<void>;
    abstract summarize(scanFilePath: string, summaryFilePath: string, projectRootFolderPath?: string): Promise<void>;

    constructor(protected readonly context: ProjectContext) { }

    public async execute(projectPath: string, outputPath: string, toolName: string): Promise<void> {
        try {
            const scanFilePath = path.join(outputPath, `${toolName}-scan.json`);
            const summaryFilePath = path.join(outputPath, `${toolName}-summary.json`);

            await this.scan(projectPath, scanFilePath);
            await this.summarize(scanFilePath, summaryFilePath, projectPath);
        } catch (error) {
            SrtLogger.logError(`Error executing ${toolName} scanner`, error as Error);
            throw error;
        }
    }
}
