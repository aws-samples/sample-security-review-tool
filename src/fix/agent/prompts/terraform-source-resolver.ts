import * as fs from 'fs/promises';
import * as path from 'path';
import { glob } from 'glob';
import { ScanResult } from '../../../assess/scanning/types.js';
import { ProjectContext } from '../../../shared/project/project-context.js';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';
import { LoadedSource } from './context-loader.js';

export class TerraformSourceResolver {
    constructor(private readonly context: ProjectContext) {}

    public async resolve(issue: ScanResult): Promise<LoadedSource | null> {
        if (!issue.resourceName || !issue.path) return null;

        const rootPath = await this.findProjectRoot(issue.path);
        if (!rootPath) return null;

        const { type, name } = this.parseResourceAddress(issue.resourceName);
        if (!type || !name) return null;

        const location = await this.findResourceInFiles(rootPath, type, name);
        if (!location) return null;

        try {
            const content = await fs.readFile(location.filePath, 'utf-8');
            return {
                path: location.filePath,
                content,
                focusLine: location.line,
                note: `Resource ${issue.resourceName} at line ${location.line} in ${path.basename(location.filePath)}.`,
            };
        } catch (error) {
            SrtLogger.logError('Failed to read Terraform source file', error as Error, {
                filePath: location.filePath,
            });
            return null;
        }
    }

    private async findProjectRoot(projectName: string): Promise<string | null> {
        const projects = await this.context.getTerraformPlans();
        const match = projects.find(p => p.name === projectName);
        return match?.rootPath ?? null;
    }

    parseResourceAddress(address: string): { type: string; name: string } {
        const stripped = address
            .replace(/^(module\.[^.]+\.)+/, '')
            .replace(/\[[^\]]*\]$/, '');

        const dotIndex = stripped.indexOf('.');
        if (dotIndex === -1) return { type: '', name: '' };

        return {
            type: stripped.substring(0, dotIndex),
            name: stripped.substring(dotIndex + 1),
        };
    }

    private async findResourceInFiles(
        rootPath: string,
        resourceType: string,
        resourceName: string,
    ): Promise<{ filePath: string; line: number } | null> {
        const tfFiles = await glob('**/*.tf', { cwd: rootPath, absolute: true });

        const escapedType = this.escapeRegex(resourceType);
        const escapedName = this.escapeRegex(resourceName);
        const pattern = new RegExp(`^[^\\S\\n]*resource\\s+"${escapedType}"\\s+"${escapedName}"\\s*\\{`, 'm');

        for (const filePath of tfFiles) {
            try {
                const content = await fs.readFile(filePath, 'utf-8');
                const match = pattern.exec(content);
                if (match) {
                    const line = content.substring(0, match.index).split('\n').length;
                    return { filePath, line };
                }
            } catch {
                continue;
            }
        }

        return null;
    }

    private escapeRegex(str: string): string {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
}
