import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import { externalCheck } from '../../../src/assess/scanning/remediation/external-check.js';

export class RelatedRulesRecorder {
    private readonly rulesRootPath: string;

    constructor(private readonly context: RuleContext) {
        this.rulesRootPath = path.join(context.srtRootFolderPath, 'src', 'assess', 'scanning', 'security-matrix', 'rules');
    }

    public async record(triggeredCheckIds: string[]): Promise<string[]> {
        const uniqueCheckIds = Array.from(new Set(triggeredCheckIds));
        let content = await fs.promises.readFile(this.context.ruleControlFilePath, 'utf8');

        const resolved = uniqueCheckIds.map(id => this.resolve(id));
        const unresolvable = resolved.filter(r => r === null);
        if (unresolvable.length > 0) this.failOnUnresolvable(uniqueCheckIds, resolved);

        const newlyRecorded = (resolved as ResolvedRule[]).filter(rule => !content.includes(rule.reference));
        if (newlyRecorded.length === 0) return [];

        const existing = (resolved as ResolvedRule[]).filter(rule => content.includes(rule.reference));
        content = this.addImports(content, newlyRecorded);
        content = this.addRelatedRulesProperty(content, [...existing, ...newlyRecorded]);
        await fs.promises.writeFile(this.context.ruleControlFilePath, content, 'utf8');

        return newlyRecorded.map(rule => rule.checkId);
    }

    private resolve(checkId: string): ResolvedRule | null {
        return this.resolveControl(checkId) ?? this.resolveExternalCheck(checkId);
    }

    private resolveControl(checkId: string): ResolvedRule | null {
        const safeId = checkId.replace(/[^A-Za-z0-9_.-]/g, '_').toLowerCase();
        const controlFileName = `${safeId}.control.ts`;
        const serviceFolders = fs.readdirSync(this.rulesRootPath, { withFileTypes: true }).filter(d => d.isDirectory());

        for (const serviceFolder of serviceFolders) {
            const controlPath = path.join(this.rulesRootPath, serviceFolder.name, safeId, controlFileName);
            if (fs.existsSync(controlPath)) {
                const instanceName = safeId.replace(/-/g, '') + 'Control';
                const importPath = this.buildRelativeImportPath(serviceFolder.name, safeId);
                return { checkId, reference: instanceName, importStatement: `import { ${instanceName} } from '${importPath}';` };
            }
        }
        return null;
    }

    private resolveExternalCheck(checkId: string): ResolvedRule | null {
        if (!externalCheck(checkId).intent) return null;
        return {
            checkId,
            reference: `externalCheck('${checkId}')`,
            importStatement: `import { externalCheck } from '${this.buildExternalCheckImportPath()}';`,
        };
    }

    private failOnUnresolvable(checkIds: string[], resolved: (ResolvedRule | null)[]): never {
        const unresolvable = checkIds.filter((_, index) => resolved[index] === null);
        throw new Error(
            `No remediation text exists for ${unresolvable.join(', ')}, so ${this.context.ruleId} cannot be taught to avoid it. ` +
            `Add a row for each check to the matching fixes file under src/assess/scanning (checkov_fixes.ts, bandit-fixes.ts or semgrep-fixes.ts).`
        );
    }

    private buildRelativeImportPath(service: string, safeId: string): string {
        const toFile = path.join(this.rulesRootPath, service, safeId, `${safeId}.control.js`);
        return this.relativeImport(toFile);
    }

    private buildExternalCheckImportPath(): string {
        const toFile = path.join(this.context.srtRootFolderPath, 'src', 'assess', 'scanning', 'remediation', 'external-check.js');
        return this.relativeImport(toFile);
    }

    private relativeImport(toFile: string): string {
        const fromDir = path.dirname(this.context.ruleControlFilePath);
        const relative = path.relative(fromDir, toFile);
        return relative.startsWith('.') ? relative : './' + relative;
    }

    private addImports(content: string, rules: ResolvedRule[]): string {
        const statements = Array.from(new Set(rules.map(rule => rule.importStatement)));
        const newImports = statements.filter(statement => !content.includes(statement));
        if (newImports.length === 0) return content;

        const lastImportIndex = content.lastIndexOf('import ');
        const lineEnd = content.indexOf('\n', lastImportIndex);
        return content.slice(0, lineEnd + 1) + newImports.join('\n') + '\n' + content.slice(lineEnd + 1);
    }

    private addRelatedRulesProperty(content: string, rules: ResolvedRule[]): string {
        const references = Array.from(new Set(rules.map(rule => rule.reference)));
        const relatedRulesLine = `      relatedRules: [${references.join(', ')}],`;

        if (content.includes('relatedRules:')) {
            return content.replace(/\s*relatedRules:\s*\[.*?\],?/s, '\n' + relatedRulesLine);
        }

        const superCallMatch = content.match(/super\(\{[\s\S]*?\}\)/);
        if (!superCallMatch) return content;

        const closingBrace = content.lastIndexOf('})', content.indexOf(superCallMatch[0]) + superCallMatch[0].length);
        const head = content.slice(0, closingBrace).replace(/[ \t]+$/, '');
        return head + relatedRulesLine + '\n    ' + content.slice(closingBrace);
    }
}

interface ResolvedRule {
    readonly checkId: string;
    readonly reference: string;
    readonly importStatement: string;
}
