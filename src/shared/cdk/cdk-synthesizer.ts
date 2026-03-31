import * as fs from 'fs/promises';
import * as path from 'path';
import { CommandRunner } from '../command-execution/command-runner.js';
import { SrtLogger } from '../logging/srt-logger.js';
import { ProjectContext } from '../project/project-context.js';
import { CdkProjectConfig, CdkSynthesisResult } from './types.js';

export class CdkSynthesizer {
    private readonly commandRunner = new CommandRunner();

    constructor(private readonly context: ProjectContext) { }

    public async synthesize(cdkDirectory: string): Promise<void> {
        const absCdkDir = path.resolve(cdkDirectory);
        const envOverrides = await this.getVenvOverrides();

        await this.cleanOutput(cdkDirectory);

        try {
            await this.commandRunner.exec('cdk synth', absCdkDir, true, envOverrides);
        } catch (firstError: any) {
            await this.cleanOutput(cdkDirectory);
            SrtLogger.logError('CDK synthesis failed', firstError, { cdkDirectory: absCdkDir });
            throw new Error(`CDK synthesis failed. Please manually run 'cdk synth' in '${absCdkDir}' to diagnose the issue.`);
        }
    }

    private async getVenvOverrides(): Promise<Record<string, string> | undefined> {
        const hasVenv = await this.context.hasPythonVenv();
        if (!hasVenv) return undefined;

        const venvConfig = await this.context.getPythonVenvConfig();
        const venvBinPath = path.join(venvConfig.venvDir, venvConfig.binDir);
        const currentPath = process.env.PATH || process.env.Path || '';
        const pathSep = process.platform === 'win32' ? ';' : ':';
        const newPath = `${venvBinPath}${pathSep}${currentPath}`;

        return process.platform === 'win32' ? { PATH: newPath, Path: newPath } : { PATH: newPath };
    }

    public async cleanOutput(cdkDirectory: string): Promise<void> {
        const srtCdkOutPath = path.join(cdkDirectory, 'cdk.out');

        try {
            await fs.rm(srtCdkOutPath, { recursive: true, force: true });
        } catch (error) {
            SrtLogger.logError('Failed to clean CDK output directory', error, { cdkOutPath: srtCdkOutPath });
        }
    }

    public async synthesizeProject(project: CdkProjectConfig): Promise<CdkSynthesisResult> {
        try {
            await this.synthesize(project.rootPath);
            return { project, success: true };
        } catch (error) {
            return {
                project,
                success: false,
                error: error instanceof Error ? error.message : String(error)
            };
        }
    }
}
