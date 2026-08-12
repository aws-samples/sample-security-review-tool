import * as fs from 'node:fs';
import * as path from 'node:path';
import * as url from 'node:url';
import { RuleContext } from '../shared/rule-context.js';

export interface LegacyRule {
    ruleId: string;
    service: string;
    description: string;
    sourceFilePaths: string[];
}

interface LegacyRuleFile {
    service: string;
    filePath: string;
    description: string;
}

const LEGACY_RULE_FILE_PATTERN = /\.(cf|tf)\.ts$/;
const CLOUD_FORMATION_FILE_PATTERN = /\.cf\.ts$/;

export class LegacyRuleNotFoundError extends Error { }

export class LegacyRuleReader {
    constructor(private readonly ruleId: string) { }

    public async read(): Promise<LegacyRule> {
        const files = await this.confirmRuleFiles();
        if (files.length === 0) this.failNotFound();

        return {
            ruleId: this.ruleId,
            service: this.singleService(files),
            description: this.describedBy(files).description,
            sourceFilePaths: files.map(file => file.filePath),
        };
    }

    private async confirmRuleFiles(): Promise<LegacyRuleFile[]> {
        const confirmed: LegacyRuleFile[] = [];
        for (const filePath of this.filesMentioningRuleId()) {
            const rule = await this.loadRule(filePath);
            if (rule?.id !== this.ruleId) continue;
            confirmed.push({ service: this.serviceOf(filePath), filePath, description: rule.description });
        }
        return confirmed;
    }

    private filesMentioningRuleId(): string[] {
        return this.serviceFolderPaths().flatMap(folderPath => this.matchingFilesIn(folderPath));
    }

    private serviceFolderPaths(): string[] {
        const rulesRootFolderPath = RuleContext.rulesRootFolderPath();
        return fs.readdirSync(rulesRootFolderPath, { withFileTypes: true })
            .filter(entry => entry.isDirectory())
            .map(entry => path.join(rulesRootFolderPath, entry.name));
    }

    private matchingFilesIn(folderPath: string): string[] {
        return fs.readdirSync(folderPath)
            .filter(name => LEGACY_RULE_FILE_PATTERN.test(name))
            .map(name => path.join(folderPath, name))
            .filter(filePath => fs.readFileSync(filePath, 'utf8').includes(`'${this.ruleId}'`));
    }

    private async loadRule(filePath: string): Promise<{ id: string; description: string } | undefined> {
        const module = await import(url.pathToFileURL(filePath).href);
        return module.default;
    }

    private serviceOf(filePath: string): string {
        return path.basename(path.dirname(filePath));
    }

    private singleService(files: LegacyRuleFile[]): string {
        const services = [...new Set(files.map(file => file.service))];
        if (services.length > 1) throw new Error(`Rule '${this.ruleId}' is implemented under more than one service folder (${services.join(', ')}). Convert it by hand.`);
        return services[0];
    }

    private describedBy(files: LegacyRuleFile[]): LegacyRuleFile {
        return files.find(file => CLOUD_FORMATION_FILE_PATTERN.test(file.filePath)) ?? files[0];
    }

    private failNotFound(): never {
        throw new LegacyRuleNotFoundError(`No legacy rule with id '${this.ruleId}' found under the security-matrix rules directory. Ids are the ones the rule declares itself, e.g. LAMBDA-013 or API-GW-002.`);
    }
}
