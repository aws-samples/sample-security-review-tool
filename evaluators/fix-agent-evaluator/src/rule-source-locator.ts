import * as fs from 'node:fs';
import * as path from 'node:path';
import { glob } from 'glob';

/**
 * Locates the security-matrix rule source file for a given check id so we can
 * show the reviewer agent how the rule evaluates compliance. This helps it
 * understand what "passing" actually means to the scanner and therefore what
 * is and isn't a workaround.
 */
export class RuleSourceLocator {
    private readonly rulesDir: string;

    constructor(srtRepoRoot: string) {
        this.rulesDir = path.join(srtRepoRoot, 'src', 'assess', 'scanning', 'security-matrix', 'rules');
    }

    public async findRuleSource(checkId: string): Promise<string> {
        if (!checkId) return '';
        const files = await glob('**/*.ts', { cwd: this.rulesDir, nodir: true });
        for (const relative of files) {
            const absolute = path.join(this.rulesDir, relative);
            const contents = this.safeRead(absolute);
            if (contents === null) continue;
            if (this.isRuleForCheckId(contents, checkId)) {
                return `// File: ${path.relative(path.dirname(this.rulesDir), absolute)}\n${contents}`;
            }
        }
        return '';
    }

    private isRuleForCheckId(contents: string, checkId: string): boolean {
        const quoted = `'${checkId}'`;
        const doubleQuoted = `"${checkId}"`;
        return contents.includes(quoted) || contents.includes(doubleQuoted);
    }

    private safeRead(absolutePath: string): string | null {
        try {
            return fs.readFileSync(absolutePath, 'utf8');
        } catch {
            return null;
        }
    }
}
