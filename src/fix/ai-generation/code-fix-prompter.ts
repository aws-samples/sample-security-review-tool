import * as path from 'path';
import { sendPrompt } from '../../shared/ai/bedrock-client.js';
import { NodeFileReader } from '../../shared/file-system/node-file-reader.js';
import { ScanResult } from '../../assess/scanning/types.js';
import { Fix, FixChange } from '../types.js';

export class CodeFixPrompter {
    private readonly fileReader = new NodeFileReader();

    private readonly languageMap: Record<string, string> = {
        '.py': 'Python',
        '.js': 'JavaScript',
        '.ts': 'TypeScript',
        '.tsx': 'TypeScript React',
        '.jsx': 'JavaScript React',
        '.go': 'Go',
        '.java': 'Java',
        '.rb': 'Ruby',
        '.php': 'PHP',
        '.cs': 'C#',
        '.rs': 'Rust',
        '.kt': 'Kotlin',
        '.kts': 'Kotlin',
        '.swift': 'Swift',
        '.scala': 'Scala',
        '.c': 'C',
        '.cpp': 'C++',
        '.cc': 'C++',
        '.h': 'C/C++ Header',
        '.hpp': 'C++ Header',
    };

    public async generateFix(projectRootFolderPath: string, issue: ScanResult): Promise<Fix | null> {
        if (!issue.path || !issue.issue || !issue.fix) {
            return null;
        }

        const filePath = path.join(projectRootFolderPath, issue.path);
        const fileContent = await this.fileReader.readTextFile(filePath);

        if (!fileContent) {
            return null;
        }

        const language = this.detectLanguage(issue.path);
        const prompt = this.buildPrompt(fileContent, issue, language);
        const response = await sendPrompt(prompt);
        const changes = await this.parseChanges(response, projectRootFolderPath, filePath, fileContent);

        if (changes.length === 0) {
            return null;
        }

        return {
            changes,
            comments: response.match(/<comments>([\s\S]*?)<\/comments>/)?.[1]?.trim() || ''
        };
    }

    private detectLanguage(filePath: string): string {
        const ext = path.extname(filePath).toLowerCase();
        return this.languageMap[ext] || 'code';
    }

    private buildPrompt(fileContent: string, issue: ScanResult, language: string): string {
        return `You are a security expert fixing a ${language} security issue.

<file path="${issue.path}">
${fileContent}
</file>

<issue_location>
Line: ${issue.line}
Check ID: ${issue.check_id}
</issue_location>

<issue>
${issue.issue}
</issue>

<fix_guidance>
${issue.fix}
</fix_guidance>

<instructions>
Fix this security issue. You may need to modify multiple files.

For EACH change, use this format:
<change>
<file_path>relative/path/to/file</file_path>
<original>exact code to find (or empty for new file content)</original>
<updated>replacement code</updated>
</change>

For NEW files (like .env or config files), use empty <original>:
<change>
<file_path>.env</file_path>
<original></original>
<updated>SECRET_KEY=your_secure_value_here</updated>
</change>

CRITICAL:
- <original> must be an EXACT substring from the file
- Preserve ${language} indentation and formatting exactly
- Include any needed import changes as separate <change> blocks

Include explanation in <comments> tags.
</instructions>`;
    }

    private async parseChanges(
        response: string,
        projectRootFolderPath: string,
        mainFilePath: string,
        mainFileContent: string
    ): Promise<FixChange[]> {
        const changeRegex = /<change>\s*<file_path>([\s\S]*?)<\/file_path>\s*<original>([\s\S]*?)<\/original>\s*<updated>([\s\S]*?)<\/updated>\s*<\/change>/g;
        const changes: FixChange[] = [];
        const fileContentsCache = new Map<string, string>();
        fileContentsCache.set(mainFilePath, mainFileContent);

        for (const match of response.matchAll(changeRegex)) {
            const relativePath = match[1].trim();
            const filePath = path.join(projectRootFolderPath, relativePath);
            let original = match[2].replace(/\r\n/g, '\n').replace(/\s+$/, '').replace(/^[\r\n]+/, '');
            let updated = match[3].replace(/\r\n/g, '\n').replace(/\s+$/, '').replace(/^[\r\n]+/, '');

            let lineNumber = 1;
            if (original) {
                let fileContent = fileContentsCache.get(filePath);
                if (!fileContent) {
                    fileContent = await this.fileReader.readTextFile(filePath) || '';
                    fileContentsCache.set(filePath, fileContent);
                }
                lineNumber = this.findLineNumber(fileContent, original);
            }

            changes.push({ filePath, original, updated, startingLineNumber: lineNumber });
        }

        return changes;
    }

    private findLineNumber(fileContent: string, searchText: string): number {
        const normalizedFile = fileContent.replace(/\r\n/g, '\n');
        const normalizedSearch = searchText.replace(/\r\n/g, '\n');
        const index = normalizedFile.indexOf(normalizedSearch);

        if (index === -1) return 1;
        return normalizedFile.substring(0, index).split('\n').length;
    }
}
