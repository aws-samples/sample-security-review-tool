import * as path from 'path';
import * as fs from 'fs';
import { readJsonFile, readTextFile } from '../../shared/file-system/file-utils.js';
import { ScanResult } from '../../assess/scanning/types.js';
import { DashboardOptions, DashboardData, DashboardSummary, BomPackage, DiagramData, ThreatModelData } from './types.js';
import packageJson from '../../../package.json' with { type: 'json' };

export class DashboardDataTransformer {
    public async transform(options: DashboardOptions, showAll: boolean): Promise<DashboardData> {
        const issuesFilePath = path.join(options.srtFolderPath, 'issues.json');
        const bomFilePath = path.join(options.srtFolderPath, 'syft-summary.json');
        const projectSummaryPath = path.join(options.srtFolderPath, 'project-summary.md');

        let issues = await this.loadIssues(issuesFilePath);

        // When showAll is false, filter to only high-priority issues
        if (!showAll) {
            issues = issues.filter(issue => issue.priority?.toLowerCase() === 'high');
        }

        const summary = this.calculateSummary(issues, showAll);
        const projectSummary = await readTextFile(projectSummaryPath);

        return {
            meta: {
                projectName: options.projectName,
                scanDate: options.scanDate.toISOString(),
                generatedAt: new Date().toISOString(),
                toolVersion: packageJson.version
            },
            summary,
            issues,
            threatModels: await this.discoverThreatModels(options.srtFolderPath),
            diagrams: await this.discoverDiagrams(options.srtFolderPath),
            bom: fs.existsSync(bomFilePath) ? await this.loadBom(bomFilePath) : null,
            projectSummary: projectSummary || null,
            showAll
        };
    }

    private async discoverThreatModels(srtFolderPath: string): Promise<ThreatModelData[]> {
        const result: ThreatModelData[] = [];
        await this.findFilesRecursively(srtFolderPath, 'threat-model-report.md', async (filePath, stackName) => {
            const content = await readTextFile(filePath);
            if (content) {
                result.push({
                    stackName,
                    content: this.cleanThreatModelContent(content)
                });
            }
        });
        return result;
    }

    private async discoverDiagrams(srtFolderPath: string): Promise<DiagramData[]> {
        const result: DiagramData[] = [];
        await this.findFilesRecursively(srtFolderPath, 'diagram.md', async (filePath, stackName) => {
            const content = await readTextFile(filePath);
            if (content) {
                result.push({
                    stackName,
                    content: this.extractMermaidCode(content)
                });
            }
        });
        return result;
    }

    private async findFilesRecursively(
        dirPath: string,
        targetFile: string,
        onFound: (filePath: string, stackName: string) => Promise<void>
    ): Promise<void> {
        const entries = fs.readdirSync(dirPath, { withFileTypes: true });

        for (const entry of entries) {
            if (!entry.isDirectory()) continue;

            const subPath = path.join(dirPath, entry.name);
            const targetPath = path.join(subPath, targetFile);

            if (fs.existsSync(targetPath)) {
                await onFound(targetPath, entry.name);
            } else {
                await this.findFilesRecursively(subPath, targetFile, onFound);
            }
        }
    }

    private cleanThreatModelContent(content: string): string {
        return content.replace(/^# CloudFormation Threat Model Report\s*/m, '').trim();
    }

    private extractMermaidCode(content: string): string {
        const normalized = content.replace(/\r\n/g, '\n').trim();
        const match = normalized.match(/```mermaid\s*\n?([\s\S]*?)```/);
        if (match) {
            return match[1].trim();
        }
        if (normalized.startsWith('flowchart') || normalized.startsWith('graph')) {
            return normalized;
        }
        return normalized.replace(/^```mermaid\s*/i, '').replace(/```\s*$/, '').trim();
    }

    private async loadIssues(issuesFilePath: string): Promise<ScanResult[]> {
        const issues = await readJsonFile<ScanResult[]>(issuesFilePath);
        if (!issues) return [];
        return issues.filter(issue => issue.status?.toLowerCase() !== 'resolved');
    }

    private async loadBom(bomFilePath: string): Promise<BomPackage[] | null> {
        const bomData = await readJsonFile<any[]>(bomFilePath);
        if (!bomData) return null;

        if (bomData.length === 1 && bomData[0].packages) {
            return this.flattenSyftPackages(bomData[0]);
        }

        return bomData.map(item => ({
            type: item.Type || item.type || '',
            name: item.Name || item.name || '',
            version: item.Version || item.version || '',
            license: item.License || item.license || '',
            path: item.Path || item.path || ''
        }));
    }

    private flattenSyftPackages(syftData: any): BomPackage[] {
        const packages: BomPackage[] = [];
        if (syftData.packages) {
            for (const packageType of syftData.packages) {
                for (const pkg of packageType.packages || []) {
                    packages.push({
                        type: packageType.type || '',
                        name: pkg.name || '',
                        version: pkg.version || '',
                        license: pkg.license || '',
                        path: pkg.path || ''
                    });
                }
            }
        }
        return packages;
    }

    private calculateSummary(issues: ScanResult[], showAll: boolean): DashboardSummary {
        const nonCustomIssues = issues.filter(i => !i.isCustomResource);
        const highPriorityIssues = nonCustomIssues.filter(i => i.priority?.toLowerCase() === 'high');

        const open = highPriorityIssues.filter(i => !i.status || i.status.toLowerCase() === 'open').length;
        const reopened = highPriorityIssues.filter(i => i.status?.toLowerCase() === 'reopened').length;
        const resolved = highPriorityIssues.filter(i => i.status?.toLowerCase() === 'fixed').length;
        const suppressed = highPriorityIssues.filter(i => i.status?.toLowerCase() === 'suppressed').length;

        const bySource: Record<string, number> = {};
        for (const issue of nonCustomIssues) {
            const source = issue.source || 'Unknown';
            bySource[source] = (bySource[source] || 0) + 1;
        }

        return {
            total: nonCustomIssues.length,
            blocking: highPriorityIssues.length,
            open,
            reopened,
            resolved,
            suppressed,
            byPriority: {
                high: nonCustomIssues.filter(i => i.priority?.toLowerCase() === 'high').length,
                medium: showAll ? nonCustomIssues.filter(i => i.priority?.toLowerCase() === 'medium').length : 0,
                low: showAll ? nonCustomIssues.filter(i => i.priority?.toLowerCase() === 'low').length : 0
            },
            bySource
        };
    }
}
