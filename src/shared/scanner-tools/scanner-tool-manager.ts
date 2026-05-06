import { ScanTool, ToolConfig } from './types.js';
import { UvManager } from './uv-manager.js';

interface ToolInvocation {
    packageName: string;
    executable: string;
}

const TOOL_MAP: Record<string, ToolInvocation> = {
    [ScanTool.CHECKOV]: { packageName: 'checkov', executable: 'checkov' },
    [ScanTool.SEMGREP]: { packageName: 'semgrep', executable: 'semgrep' },
    [ScanTool.BANDIT]: { packageName: 'bandit', executable: 'bandit' },
    [ScanTool.SYFT]: { packageName: 'anchore_syft', executable: 'syft' },
    [ScanTool.JUPYTER]: { packageName: 'jupyter', executable: 'jupyter' },
    [ScanTool.CFN_LINT]: { packageName: 'cfn-lint', executable: 'cfn-lint' },
};

export class ScannerToolManager {
    private config: ToolConfig | null = null;

    public async getToolConfig(): Promise<ToolConfig> {
        if (!this.config) {
            const uvPath = await UvManager.ensureUvAvailable();
            this.config = { uvPath };
        }
        return this.config;
    }

    public static getToolRunPrefix(uvPath: string, tool: ScanTool | string): string {
        const invocation = TOOL_MAP[tool.toString()];
        if (!invocation) {
            return `"${uvPath}" tool run --from ${tool} ${tool}`;
        }

        return `"${uvPath}" tool run --from ${invocation.packageName} ${invocation.executable}`;
    }

    public static getToolRunArgs(tool: ScanTool | string): string[] {
        const invocation = TOOL_MAP[tool.toString()];
        if (!invocation) {
            return ['tool', 'run', '--from', tool.toString(), tool.toString()];
        }

        return ['tool', 'run', '--from', invocation.packageName, invocation.executable];
    }

    public static extractToolName(command: string): string {
        const toLower = command.toLowerCase();

        if (toLower.includes('nbconvert')) return 'Jupyter nbconvert';

        for (const [, value] of Object.entries(ScanTool)) {
            let toolKey = (value as string).toLowerCase();
            if (toolKey === 'anchore_syft') toolKey = 'syft';

            if (toLower.includes(toolKey)) {
                return toolKey.charAt(0).toUpperCase() + toolKey.slice(1);
            }
        }

        return 'Tool';
    }

    public static getAllScanTools(): ScanTool[] {
        return [ScanTool.CHECKOV, ScanTool.SEMGREP, ScanTool.SYFT, ScanTool.BANDIT, ScanTool.JUPYTER, ScanTool.CFN_LINT];
    }
}
