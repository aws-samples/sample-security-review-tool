import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import type { LegacyRule } from './legacy-rule-reader.js';

const LEGACY_RULE_FILE_SUFFIX_PATTERN = /\.(cf|tf)\.ts$/;
const MODULE_SPECIFIER_PATTERN = /\bfrom\s+'\.\/(.+?)'/;
const BINDING_PATTERNS = [
    /^import\s+(\w+)\s+from\s+'\.\//,
    /^export\s*\{\s*default\s+as\s+(\w+)\s*\}\s*from\s+'\.\//,
];
const LOCAL_MODULE_PATTERN = /\bfrom\s+'\.\//;
const EXPORTED_ARRAY_PATTERN = /^export const (\w+)/gm;

export class LegacyRuleRemover {
    constructor(private readonly legacy: LegacyRule) { }

    public remove(): string[] {
        const removedPaths = [...this.deleteRuleFiles(), ...this.deregister()];
        return removedPaths.map(filePath => path.relative(RuleContext.srtRootFolderPath(), filePath));
    }

    private deleteRuleFiles(): string[] {
        return [...this.legacy.sourceFilePaths, ...this.testFilePaths()]
            .filter(filePath => fs.existsSync(filePath))
            .map(filePath => {
                fs.rmSync(filePath);
                return filePath;
            });
    }

    private testFilePaths(): string[] {
        const testFolderPath = path.join(RuleContext.srtRootFolderPath(), 'tests', 'core', 'scanners', 'srt', 'rules', this.legacy.service);
        const fileNames = this.legacy.sourceFilePaths.map(filePath => `${path.basename(filePath).replace(LEGACY_RULE_FILE_SUFFIX_PATTERN, '')}.test.ts`);
        return [...new Set(fileNames)].map(fileName => path.join(testFolderPath, fileName));
    }

    private deregister(): string[] {
        const indexPath = path.join(RuleContext.rulesRootFolderPath(), this.legacy.service, 'index.ts');
        if (!fs.existsSync(indexPath)) return [];

        const content = fs.readFileSync(indexPath, 'utf8');
        const lines = content.split('\n');
        const legacyLines = lines.filter(line => this.referencesLegacyModule(line));
        const boundNames = legacyLines.flatMap(line => this.boundNames(line));

        const remaining = lines.filter(line => !legacyLines.includes(line) && !this.mentionsAny(line, boundNames));

        if (this.stillRegistersRules(remaining)) {
            fs.writeFileSync(indexPath, remaining.join('\n'));
            return [indexPath];
        }

        fs.rmSync(indexPath);
        return [indexPath, ...this.deregisterService(content)];
    }

    private referencesLegacyModule(line: string): boolean {
        const specifier = MODULE_SPECIFIER_PATTERN.exec(line);
        if (!specifier) return false;

        const legacyModuleNames = this.legacy.sourceFilePaths.map(filePath => path.basename(filePath).replace(/\.ts$/, '.js'));
        return legacyModuleNames.includes(specifier[1]);
    }

    private boundNames(line: string): string[] {
        return BINDING_PATTERNS
            .map(pattern => pattern.exec(line))
            .filter(match => match !== null)
            .map(match => match![1]);
    }

    private mentionsAny(line: string, names: string[]): boolean {
        return names.length > 0 && names.some(name => new RegExp(`\\b${name}\\b`).test(line));
    }

    private stillRegistersRules(lines: string[]): boolean {
        return lines.some(line => LOCAL_MODULE_PATTERN.test(line));
    }

    private deregisterService(serviceIndexContent: string): string[] {
        const registryPath = path.join(RuleContext.rulesRootFolderPath(), 'index.ts');
        const arrayNames = [...serviceIndexContent.matchAll(EXPORTED_ARRAY_PATTERN)].map(match => match[1]);
        const lines = fs.readFileSync(registryPath, 'utf8').split('\n');

        fs.writeFileSync(registryPath, lines.filter(line => !this.mentionsAny(line, arrayNames)).join('\n'));
        return [registryPath];
    }
}
