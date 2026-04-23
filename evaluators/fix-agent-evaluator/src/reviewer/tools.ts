import * as fs from 'node:fs';
import * as path from 'node:path';
import { glob } from 'glob';

/**
 * Read-only filesystem tools exposed to the reviewer agent. All paths are
 * resolved against the target project root and must not escape it.
 */
export class ReviewerTools {
    constructor(private readonly projectRoot: string) {}

    public async listFiles(pattern: string): Promise<string[]> {
        const matches = await glob(pattern, {
            cwd: this.projectRoot,
            nodir: true,
            ignore: ['**/node_modules/**', '**/build/**', '**/.git/**'],
        });
        return matches.slice(0, 200);
    }

    public async grep(pattern: string, pathGlob?: string): Promise<string> {
        const files = await this.listFiles(pathGlob ?? '**/*.{ts,js,py,json,yaml,yml}');
        const regex = this.safeRegExp(pattern);
        const hits: string[] = [];
        for (const relative of files) {
            const contents = this.safeRead(path.join(this.projectRoot, relative));
            if (contents === null) continue;
            const lines = contents.split('\n');
            lines.forEach((line, index) => {
                if (regex.test(line)) {
                    hits.push(`${relative}:${index + 1}: ${line.trim()}`);
                }
            });
            if (hits.length >= 200) return hits.slice(0, 200).join('\n') + '\n[truncated]';
        }
        return hits.join('\n');
    }

    public readFile(relativePath: string): string {
        const absolute = path.resolve(this.projectRoot, relativePath);
        if (!absolute.startsWith(this.projectRoot)) {
            throw new Error(`Refusing to read path outside project: ${relativePath}`);
        }
        const contents = this.safeRead(absolute);
        if (contents === null) throw new Error(`File not found: ${relativePath}`);
        return contents;
    }

    private safeRead(absolutePath: string): string | null {
        try {
            if (!fs.existsSync(absolutePath)) return null;
            return fs.readFileSync(absolutePath, 'utf8');
        } catch {
            return null;
        }
    }

    private safeRegExp(pattern: string): RegExp {
        try {
            return new RegExp(pattern);
        } catch {
            return new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
        }
    }
}
