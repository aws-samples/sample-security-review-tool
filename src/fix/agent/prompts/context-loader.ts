import * as fs from 'fs/promises';
import * as path from 'path';
import { ScanResult } from '../../../assess/scanning/types.js';
import { ProjectContext } from '../../../shared/project/project-context.js';
import { CdkConstructResolver } from '../../cdk/cdk-construct-resolver.js';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';

export interface LoadedSource {
    path: string;
    content: string;
    focusLine?: number;
    note?: string;
}

export interface LoadedContext {
    sources: LoadedSource[];
}

/**
 * Deterministically pre-loads the source context the agent needs to reason
 * about the finding. Uses the richest available signal on the ScanResult:
 * the cdkPath resolves directly to the CDK source file, otherwise we fall
 * back to the finding's own path.
 */
export class ContextLoader {
    private readonly cdkResolver: CdkConstructResolver;

    constructor(private readonly context: ProjectContext) {
        this.cdkResolver = new CdkConstructResolver(context);
    }

    public async load(issue: ScanResult): Promise<LoadedContext> {
        if (issue.cdkPath) {
            const cdkSource = await this.loadCdkSource(issue);
            if (cdkSource) return { sources: [cdkSource] };
        }
        const fallback = await this.loadFallbackSource(issue);
        return { sources: fallback ? [fallback] : [] };
    }

    private async loadCdkSource(issue: ScanResult): Promise<LoadedSource | null> {
        try {
            const resolved = await this.cdkResolver.findConstructForIssue(issue.cdkPath!, issue.path);
            if (!resolved) return null;
            return {
                path: resolved.filePath,
                content: resolved.context,
                focusLine: resolved.lineNumber,
                note: `Construct ${issue.cdkPath} starts at line ${resolved.lineNumber} in ${resolved.filePath}.`,
            };
        } catch (error) {
            SrtLogger.logError('Failed to resolve CDK construct for fix agent', error as Error, {
                cdkPath: issue.cdkPath,
                path: issue.path,
            });
            return null;
        }
    }

    private async loadFallbackSource(issue: ScanResult): Promise<LoadedSource | null> {
        if (!issue.path) return null;
        const absolutePath = this.resolveIssuePath(issue.path);
        try {
            const content = await fs.readFile(absolutePath, 'utf-8');
            return {
                path: absolutePath,
                content,
                focusLine: issue.line,
            };
        } catch (error) {
            SrtLogger.logError('Failed to read finding source file', error as Error, {
                path: issue.path,
                resolved: absolutePath,
            });
            return null;
        }
    }

    private resolveIssuePath(issuePath: string): string {
        if (path.isAbsolute(issuePath)) return issuePath;
        return path.resolve(this.context.getProjectRootFolderPath(), issuePath);
    }
}
