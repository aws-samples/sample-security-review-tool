import { readFileSync, readdirSync, statSync } from 'fs';
import path from 'path';

export class GitIgnoreToGlob {

    constructor(private readonly projectRootFolderPath: string) { }

    public read(): string[] {
        const allPatterns: string[] = [];
        const gitignoreFiles = this.findAllGitignoreFiles(this.projectRootFolderPath);

        for (const gitignoreFile of gitignoreFiles) {
            try {
                const content = readFileSync(gitignoreFile.path, 'utf-8');
                const patterns = this.parse(content, gitignoreFile.directory);
                allPatterns.push(...patterns);
            } catch (error) {
                // Silent failure for unreadable .gitignore files
            }
        }

        const uniquePatterns = [...new Set(allPatterns)];
        return uniquePatterns;
    }

    private findAllGitignoreFiles(dir: string): Array<{path: string, directory: string}> {
        const gitignoreFiles: Array<{path: string, directory: string}> = [];

        try {
            const entries = readdirSync(dir);

            for (const entry of entries) {
                const fullPath = path.join(dir, entry);

                try {
                    const stat = statSync(fullPath);

                    if (stat.isFile() && entry === '.gitignore') {
                        gitignoreFiles.push({ path: fullPath, directory: dir });
                    } else if (stat.isDirectory() && !entry.startsWith('.') && entry !== 'node_modules') {
                        gitignoreFiles.push(...this.findAllGitignoreFiles(fullPath));
                    }
                } catch (error) {
                    // Silently skip inaccessible files
                }
            }
        } catch (error) {
            // Silently skip unreadable directories
        }

        return gitignoreFiles;
    }

    private parse(content: string, gitignoreDirectory: string): string[] {
        const lines = content.split('\n');
        const patterns: string[] = [];

        for (const line of lines) {
            const trimmed = line.trim();

            if (!trimmed || trimmed.startsWith('#')) continue;

            patterns.push(...this.convertPattern(trimmed, gitignoreDirectory));
        }

        return patterns;
    }

    private convertPattern(pattern: string, gitignoreDirectory: string): string[] {
        const results: string[] = [];
        let processed = pattern;

        const isNegated = processed.startsWith('!');
        if (isNegated) {
            processed = processed.substring(1);
        }

        processed = processed.replace(/\s+$/, '');

        const isRootOnly = processed.startsWith('/');
        if (isRootOnly) {
            processed = processed.substring(1);
        }

        const isDirectoryOnly = processed.endsWith('/');
        if (isDirectoryOnly) {
            processed = processed.slice(0, -1);
        }

        const baseDir = gitignoreDirectory;

        if (isRootOnly) {
            const basePattern = baseDir ? path.join(baseDir, processed).replace(/\\/g, '/') : processed;

            results.push(basePattern);
            if (isDirectoryOnly || !this.isObviouslyAFile(processed)) {
                results.push(`${basePattern}/**`);
            }
        } else {
            const basePattern = baseDir ? path.join(baseDir, '**', processed).replace(/\\/g, '/') : `**/${processed}`;

            results.push(basePattern);
            if (isDirectoryOnly || !this.isObviouslyAFile(processed)) {
                results.push(`${basePattern}/**`);
            }
        }

        if (isNegated) {
            return results.map(p => `!${p}`);
        }

        return results;
    }

    private isObviouslyAFile(pattern: string): boolean {
        if (pattern.includes('*')) {
            return /\*\.[a-zA-Z0-9]+/.test(pattern);
        }

        const lastSegment = pattern.split('/').pop() || '';
        return /\.(js|ts|json|txt|md|html|css|py|java|cpp|c|h)$/i.test(lastSegment);
    }
}
