import path from 'path';
import fs from 'fs/promises';
import { SrtLogger } from '../logging/srt-logger.js';
import { CommandRunner } from '../command-execution/command-runner.js';
import { AppPaths } from '../app-config/app-paths.js';
import { ScanTool, AuxiliaryTool, VenvConfig } from './types.js';

export class ScannerToolManager {
    private readonly cmd: CommandRunner;
    private readonly config: VenvConfig;

    constructor() {
        this.cmd = new CommandRunner();
        this.config = this.initializeConfig();
    }

    private initializeConfig(): VenvConfig {
        const venvDir = path.join(AppPaths.getAppDir(), '.venv');
        const platform = process.platform;
        const pythonCmd = (platform === 'darwin' || platform === 'linux') ? 'python3' : 'python';
        const binDir = (platform === 'darwin' || platform === 'linux') ? 'bin' : 'Scripts';

        const pythonExe = platform === 'win32' ? 'python.exe' : 'python';
        const pythonPath = path.join(venvDir, binDir, pythonExe);

        return {
            rootDir: AppPaths.getAppDir(),
            venvDir,
            binDir,
            pythonCmd,
            pythonPath,
            checkovCmd: path.join(venvDir, binDir, ScannerToolManager.addExecutableExtension('checkov', platform)),
            semgrepCmd: path.join(venvDir, binDir, ScannerToolManager.addExecutableExtension('semgrep', platform)),
            banditCmd: path.join(venvDir, binDir, ScannerToolManager.addExecutableExtension('bandit', platform)),
            syftCmd: path.join(venvDir, binDir, ScannerToolManager.addExecutableExtension('syft', platform)),
            jupyterlabCmd: path.join(venvDir, binDir, ScannerToolManager.addExecutableExtension('jupyter', platform))
        };
    }

    public static extractToolName(command: string): string {
        const toLower = command.toLowerCase();

        if (toLower.includes('nbconvert')) {
            return 'Jupyter nbconvert';
        }

        const checkToolMatch = (
            toolEnum: typeof AuxiliaryTool | typeof ScanTool,
            transform?: (value: string) => string
        ): string | null => {
            for (const [key, value] of Object.entries(toolEnum)) {
                if (!isNaN(Number(key))) continue;

                let toolKey = (value as string).toLowerCase();
                if (transform) {
                    toolKey = transform(toolKey);
                }

                if (toLower.includes(toolKey)) {
                    return toolKey.charAt(0).toUpperCase() + toolKey.slice(1);
                }
            }
            return null;
        };

        return checkToolMatch(AuxiliaryTool) ||
            checkToolMatch(ScanTool, value => value === 'anchore_syft' ? 'syft' : value) ||
            "Tool";
    }

    public static addExecutableExtension(toolName: string, platform: NodeJS.Platform): string {
        if (platform !== 'win32' || toolName === 'checkov') {
            return toolName;
        }
        return `${toolName}.exe`;
    }

    public async ensureVenvExists(): Promise<void> {
        const { rootDir, venvDir, pythonCmd } = this.config;

        try {
            await fs.access(venvDir);
        } catch {
            try {
                await this.cmd.exec(`${pythonCmd} -m venv "${venvDir}"`, rootDir);
            } catch (err) {
                const errorMsg = `Failed to create virtual environment`;
                SrtLogger.logError(errorMsg, err as Error);
                throw new Error(errorMsg);
            }
        }
    }

    public async verifyToolInstalled(tool: ScanTool | string): Promise<void> {
        const cmdTool = tool === ScanTool.SYFT ? 'syft' : tool;
        const toolPath = this.getToolPath(cmdTool.toString());
        const isInstalled = await this.fileExists(toolPath);

        if (!isInstalled) await this.installTool(tool);
    }

    public async isToolInstalled(tool: ScanTool | string): Promise<boolean> {
        const cmdTool = tool === ScanTool.SYFT ? 'syft' : tool;
        const toolPath = this.getToolPath(cmdTool.toString());
        return this.fileExists(toolPath);
    }

    private async fileExists(filePath: string): Promise<boolean> {
        return fs.access(filePath, fs.constants.F_OK)
            .then(() => true)
            .catch(() => false);
    }

    public getVenvConfig(): VenvConfig {
        return this.config;
    }

    public getToolPath(tool: string): string {
        const toolName = ScannerToolManager.addExecutableExtension(tool, process.platform);
        return path.join(this.config.venvDir, this.config.binDir, toolName);
    }

    public async installTool(tool: ScanTool | string): Promise<void> {
        const { pythonPath, rootDir } = this.config;
        const scannerStr = tool.toString();
        const cmdTool = scannerStr === ScanTool.SYFT ? 'syft' : scannerStr;
        const toolPath = this.getToolPath(cmdTool);

        try {
            const noCacheOption = process.platform === 'win32' ? '--no-cache-dir' : '';

            try {
                await this.cmd.exec(`"${pythonPath}" -m pip install ${noCacheOption} --upgrade ${scannerStr}`, rootDir);
            } catch {
                await this.cmd.exec(`"${pythonPath}" -m pip install --user --upgrade jupyter`, rootDir);
            }

            await this.cmd.exec(`"${pythonPath}" "${toolPath}" --version`, rootDir);
        } catch (error) {
            const errorMsg = `Failed to verify ${tool} installation`;
            SrtLogger.logError(errorMsg, error as Error);
            throw new Error(errorMsg);
        }
    }

    public static getAllScanTools(): ScanTool[] {
        return [ScanTool.CHECKOV, ScanTool.SEMGREP, ScanTool.SYFT, ScanTool.BANDIT, ScanTool.JUPYTER];
    }
}
