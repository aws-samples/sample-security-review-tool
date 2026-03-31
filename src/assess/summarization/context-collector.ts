import * as fs from 'fs/promises';
import * as path from 'path';
import { readTextFile } from '../../shared/file-system/file-utils.js';
import { TemplateResult } from '../types.js';

export class ContextCollector {
    private static readonly MAX_README_LENGTH = 3000;
    private static readonly EXCLUDED_DIRS = ['node_modules', '.git', '.srt', '.venv', '.srt-venv', 'cdk.out', 'dist', 'build', '__pycache__'];

    public async collect(projectPath: string, templateResults: TemplateResult[]): Promise<string> {
        const sections: string[] = [];

        const readme = await this.collectReadme(projectPath);
        if (readme) {
            sections.push(`## README\n${readme}`);
        }

        const cfnResources = await this.collectCfnResources(templateResults);
        if (cfnResources) {
            sections.push(`## CloudFormation Resources\n${cfnResources}`);
        }

        const fileTypes = await this.collectFileTypes(projectPath);
        if (fileTypes) {
            sections.push(`## File Types\n${fileTypes}`);
        }

        const folderStructure = await this.collectFolderStructure(projectPath);
        if (folderStructure) {
            sections.push(`## Folder Structure\n${folderStructure}`);
        }

        return sections.join('\n\n');
    }

    private async collectReadme(projectPath: string): Promise<string | null> {
        const readmeNames = ['README.md', 'readme.md', 'README.MD', 'Readme.md', 'README', 'readme'];

        for (const name of readmeNames) {
            const readmePath = path.join(projectPath, name);
            try {
                const content = await readTextFile(readmePath);
                if (content) {
                    if (content.length > ContextCollector.MAX_README_LENGTH) {
                        return content.substring(0, ContextCollector.MAX_README_LENGTH) + '\n... (truncated)';
                    }
                    return content;
                }
            } catch {
                // File doesn't exist, try next
            }
        }

        return null;
    }

    private async collectCfnResources(templateResults: TemplateResult[]): Promise<string | null> {
        if (templateResults.length === 0) {
            return null;
        }

        const resourceTypes = new Set<string>();

        for (const result of templateResults) {
            try {
                const content = await readTextFile(result.cfnTemplateFilePath);
                if (!content) continue;

                const types = this.extractResourceTypes(content, result.cfnTemplateFilePath);
                types.forEach(t => resourceTypes.add(t));
            } catch (error) {
            }
        }

        if (resourceTypes.size === 0) {
            return null;
        }

        const sortedTypes = Array.from(resourceTypes).sort();
        return sortedTypes.map(t => `- ${t}`).join('\n');
    }

    private extractResourceTypes(content: string, filePath: string): string[] {
        const types: string[] = [];

        try {
            if (filePath.endsWith('.json')) {
                const parsed = JSON.parse(content);
                if (parsed.Resources) {
                    for (const resource of Object.values(parsed.Resources) as any[]) {
                        if (resource.Type) {
                            types.push(resource.Type);
                        }
                    }
                }
            } else {
                // YAML - use regex for simplicity
                const typeMatches = content.matchAll(/^\s*Type:\s*['"]?(AWS::[^\s'"]+)/gm);
                for (const match of typeMatches) {
                    types.push(match[1]);
                }
            }
        } catch (error) {
        }

        return types;
    }

    private async collectFileTypes(projectPath: string): Promise<string | null> {
        const extensionCounts = new Map<string, number>();

        try {
            await this.countFileExtensions(projectPath, extensionCounts);
        } catch (error) {
            return null;
        }

        if (extensionCounts.size === 0) {
            return null;
        }

        const sorted = Array.from(extensionCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15);

        return sorted.map(([ext, count]) => `- ${ext}: ${count} files`).join('\n');
    }

    private async countFileExtensions(dir: string, counts: Map<string, number>): Promise<void> {
        try {
            const entries = await fs.readdir(dir, { withFileTypes: true });

            for (const entry of entries) {
                if (entry.isDirectory()) {
                    if (!ContextCollector.EXCLUDED_DIRS.includes(entry.name)) {
                        await this.countFileExtensions(path.join(dir, entry.name), counts);
                    }
                } else if (entry.isFile()) {
                    const ext = path.extname(entry.name).toLowerCase() || '(no extension)';
                    counts.set(ext, (counts.get(ext) || 0) + 1);
                }
            }
        } catch {
            // Ignore permission errors
        }
    }

    private async collectFolderStructure(projectPath: string): Promise<string | null> {
        try {
            const entries = await fs.readdir(projectPath, { withFileTypes: true });
            const folders = entries
                .filter(e => e.isDirectory() && !ContextCollector.EXCLUDED_DIRS.includes(e.name) && !e.name.startsWith('.'))
                .map(e => e.name)
                .sort();

            if (folders.length === 0) {
                return null;
            }

            return folders.map(f => `- ${f}/`).join('\n');
        } catch (error) {
            return null;
        }
    }
}
