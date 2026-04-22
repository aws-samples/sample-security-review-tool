import * as path from 'path';
import { ScanResult } from '../../../assess/scanning/types.js';
import { LoadedContext } from './context-loader.js';
import { renderWithLineNumbers } from './line-numbered-source.js';

export function buildUserPrompt(issue: ScanResult, projectRootFolderPath: string, loadedContext: LoadedContext): string {
    const sections: string[] = [
        renderFindingMetadata(issue),
        renderIssue(issue),
        renderGuidance(issue),
        renderSources(loadedContext, projectRootFolderPath),
    ];
    return sections.filter(section => section.length > 0).join('\n\n');
}

function renderFindingMetadata(issue: ScanResult): string {
    const lines: string[] = ['## Finding'];
    lines.push(`- Source: ${issue.source}`);
    lines.push(`- Check ID: ${issue.check_id ?? 'unknown'}`);
    lines.push(`- Priority: ${issue.priority ?? 'unknown'}`);
    if (issue.path) lines.push(`- File: ${issue.path}`);
    if (issue.line !== undefined) lines.push(`- Line: ${issue.line}`);
    if (issue.resourceType) lines.push(`- Resource type: ${issue.resourceType}`);
    if (issue.resourceName) lines.push(`- Resource name: ${issue.resourceName}`);
    if (issue.cdkPath) lines.push(`- CDK path: ${issue.cdkPath}`);
    return lines.join('\n');
}

function renderIssue(issue: ScanResult): string {
    return `## Issue\n${issue.issue ?? '(none)'}`;
}

function renderGuidance(issue: ScanResult): string {
    return `## Fix guidance\n${issue.fix ?? '(none)'}`;
}

function renderSources(loadedContext: LoadedContext, projectRootFolderPath: string): string {
    if (loadedContext.sources.length === 0) {
        return '## Source\n(no source available — use give_up if you cannot proceed)';
    }
    const blocks = loadedContext.sources.map(source => {
        const relativePath = toRelativePosix(source.path, projectRootFolderPath);
        const header = `### ${relativePath}`;
        const note = source.note ? `\n${source.note}` : '';
        const body = renderWithLineNumbers(source.content, { focusLine: source.focusLine });
        return `${header}${note}\n\n\`\`\`\n${body}\n\`\`\``;
    });
    return ['## Source (with line numbers)', ...blocks].join('\n\n');
}

function toRelativePosix(absolutePath: string, rootFolderPath: string): string {
    const relative = path.relative(rootFolderPath, absolutePath);
    return path.sep === '/' ? relative : relative.split(path.sep).join('/');
}
