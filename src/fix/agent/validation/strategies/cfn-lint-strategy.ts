import * as path from 'path';
import { execFile } from 'child_process';
import { FixChange } from '../../../types.js';
import { ProjectContext } from '../../../../shared/project/project-context.js';
import { UvManager } from '../../../../shared/scanner-tools/uv-manager.js';
import { ScannerToolManager } from '../../../../shared/scanner-tools/scanner-tool-manager.js';
import { ScanTool } from '../../../../shared/scanner-tools/types.js';
import { StrategyResult, ValidationStrategy } from '../types.js';

interface CfnLintFinding {
    Level: string;
    Message: string;
    Rule: { Id: string; ShortDescription: string };
    Location: { Path: string[] };
}

const TEMPLATE_EXTENSIONS = ['.yaml', '.yml', '.json'];

export class CfnLintStrategy implements ValidationStrategy {
    public readonly name = 'cfn-lint';

    public async validate(changes: FixChange[], context: ProjectContext): Promise<StrategyResult[]> {
        const templateChanges = await this.filterTemplates(changes, context);
        if (templateChanges.length === 0) return [];

        const uvPath = await UvManager.ensureUvAvailable();
        const results: StrategyResult[] = [];
        for (const change of templateChanges) {
            results.push(await this.lint(uvPath, change.filePath));
        }
        return results;
    }

    private async filterTemplates(changes: FixChange[], context: ProjectContext): Promise<FixChange[]> {
        const candidates: FixChange[] = [];
        for (const change of changes) {
            const ext = path.extname(change.filePath).toLowerCase();
            if (!TEMPLATE_EXTENSIONS.includes(ext)) continue;
            if (await context.isCloudFormationTemplate(change.filePath)) {
                candidates.push(change);
            }
        }
        return candidates;
    }

    private async lint(uvPath: string, filePath: string): Promise<StrategyResult> {
        const strategy = `${this.name}:${path.basename(filePath)}`;
        const toolArgs = ScannerToolManager.getToolRunArgs(ScanTool.CFN_LINT);
        const { exitCode, stdout, stderr } = await this.exec(uvPath, [...toolArgs, '-f', 'json', filePath]);

        if (exitCode === 0) {
            return { strategy, isValid: true };
        }

        const findings = this.parseFindings(stdout);
        const errors = findings.filter(f => f.Level === 'Error');
        if (errors.length > 0) {
            const output = errors
                .map(f => `${f.Rule.Id}: ${f.Message} (at ${f.Location.Path.join('/')})`)
                .join('\n');
            return { strategy, isValid: false, output };
        }

        const fallback = [stderr, stdout].filter(s => s.length > 0).join('\n');
        return { strategy, isValid: false, output: fallback || 'cfn-lint failed' };
    }

    private exec(command: string, args: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> {
        return new Promise(resolve => {
            execFile(command, args, (error, stdout, stderr) => {
                const exitCode = error ? (error as { code?: number }).code ?? 1 : 0;
                resolve({
                    exitCode,
                    stdout: (stdout ?? '').toString().trim(),
                    stderr: (stderr ?? '').toString().trim(),
                });
            });
        });
    }

    private parseFindings(stdout: string): CfnLintFinding[] {
        if (!stdout) return [];
        try {
            return JSON.parse(stdout) as CfnLintFinding[];
        } catch {
            return [];
        }
    }
}
