import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';

export class RelatedRulesRecorder {
    private readonly rulesRootPath: string;

    constructor(private readonly context: RuleContext) {
        this.rulesRootPath = path.join(context.srtRootFolderPath, 'src', 'assess', 'scanning', 'security-matrix', 'rules');
    }

    public async record(triggeredCheckIds: string[]): Promise<void> {
        const relatedRules = triggeredCheckIds.map(id => this.resolveControl(id)).filter(Boolean) as ResolvedControl[];
        if (relatedRules.length === 0) return;

        let content = await fs.promises.readFile(this.context.ruleControlFilePath, 'utf8');
        content = this.addImports(content, relatedRules);
        content = this.addRelatedRulesProperty(content, relatedRules);
        await fs.promises.writeFile(this.context.ruleControlFilePath, content, 'utf8');
    }

    private resolveControl(checkId: string): ResolvedControl | null {
        const safeId = checkId.replace(/[^A-Za-z0-9_.-]/g, '_').toLowerCase();
        const controlFileName = `${safeId}.control.ts`;
        const serviceFolders = fs.readdirSync(this.rulesRootPath, { withFileTypes: true }).filter(d => d.isDirectory());

        for (const serviceFolder of serviceFolders) {
            const controlPath = path.join(this.rulesRootPath, serviceFolder.name, safeId, controlFileName);
            if (fs.existsSync(controlPath)) {
                const instanceName = safeId.replace(/-/g, '') + 'Control';
                const relativePath = this.buildRelativeImportPath(serviceFolder.name, safeId);
                return { checkId, safeId, instanceName, relativePath };
            }
        }
        return null;
    }

    private buildRelativeImportPath(service: string, safeId: string): string {
        const fromDir = path.dirname(this.context.ruleControlFilePath);
        const toFile = path.join(this.rulesRootPath, service, safeId, `${safeId}.control.js`);
        let relative = path.relative(fromDir, toFile);
        if (!relative.startsWith('.')) relative = './' + relative;
        return relative;
    }

    private addImports(content: string, relatedRules: ResolvedControl[]): string {
        const newImports = relatedRules
            .filter(rule => !content.includes(rule.instanceName))
            .map(rule => `import { ${rule.instanceName} } from '${rule.relativePath}';`);
        if (newImports.length === 0) return content;

        const lastImportIndex = content.lastIndexOf('import ');
        const lineEnd = content.indexOf('\n', lastImportIndex);
        return content.slice(0, lineEnd + 1) + newImports.join('\n') + '\n' + content.slice(lineEnd + 1);
    }

    private addRelatedRulesProperty(content: string, relatedRules: ResolvedControl[]): string {
        const instanceNames = relatedRules.map(r => r.instanceName);
        const relatedRulesLine = `      relatedRules: [${instanceNames.join(', ')}],`;

        if (content.includes('relatedRules:')) {
            return content.replace(/\s*relatedRules:\s*\[.*?\],?/s, '\n' + relatedRulesLine);
        }

        const superCallMatch = content.match(/super\(\{[\s\S]*?\}\)/);
        if (!superCallMatch) return content;

        const closingBrace = content.lastIndexOf('})', content.indexOf(superCallMatch[0]) + superCallMatch[0].length);
        return content.slice(0, closingBrace) + '\n' + relatedRulesLine + '\n    ' + content.slice(closingBrace);
    }
}

interface ResolvedControl {
    readonly checkId: string;
    readonly safeId: string;
    readonly instanceName: string;
    readonly relativePath: string;
}
