import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import type { LegacyRule } from './legacy-rule-reader.js';

const LEGACY_RULE_FILE_SUFFIX_PATTERN = /\.(cf|tf)\.ts$/;
const RULE_IMPORT_PATTERN = /^import\s+(\w+)\s+from\s+'\.\/(.+)'/;
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
        const remaining = lines.filter(line => !this.mentionsAny(line, this.importedRuleNames(lines)));

        if (this.stillRegistersRules(remaining)) {
            fs.writeFileSync(indexPath, remaining.join('\n'));
            return [indexPath];
        }

        fs.rmSync(indexPath);
        return [indexPath, ...this.deregisterService(content)];
    }

    private importedRuleNames(lines: string[]): string[] {
        const legacyModuleNames = this.legacy.sourceFilePaths.map(filePath => path.basename(filePath).replace(/\.ts$/, '.js'));
        return lines
            .map(line => RULE_IMPORT_PATTERN.exec(line))
            .filter(match => match !== null && legacyModuleNames.includes(match[2]))
            .map(match => match![1]);
    }

    private mentionsAny(line: string, names: string[]): boolean {
        return names.some(name => new RegExp(`\\b${name}\\b`).test(line));
    }

    private stillRegistersRules(lines: string[]): boolean {
        return lines.some(line => RULE_IMPORT_PATTERN.test(line));
    }

    private deregisterService(serviceIndexContent: string): string[] {
        const registryPath = path.join(RuleContext.rulesRootFolderPath(), 'index.ts');
        const arrayNames = [...serviceIndexContent.matchAll(EXPORTED_ARRAY_PATTERN)].map(match => match[1]);
        const lines = fs.readFileSync(registryPath, 'utf8').split('\n');

        fs.writeFileSync(registryPath, lines.filter(line => !this.mentionsAny(line, arrayNames)).join('\n'));
        return [registryPath];
    }
}
