import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from './rule-context.js';

export class RuleNotFoundError extends Error { }

export class RuleLocator {
    constructor(private readonly ruleId: string) { }

    public locate(): RuleContext {
        const requirementsFilePath = this.findRequirementsFilePath();
        const service = this.serviceFromRequirementsPath(requirementsFilePath);
        const description = this.descriptionFromRequirementsFile(requirementsFilePath);
        return new RuleContext(this.ruleId, service, description);
    }

    private get safeRuleId(): string {
        return this.ruleId.replace(/[^A-Za-z0-9_.-]/g, '_').toLowerCase();
    }

    private get rulesRootFolderPath(): string {
        return RuleContext.rulesRootFolderPath();
    }

    private findRequirementsFilePath(): string {
        const fileName = `${this.safeRuleId}.requirements.json`;
        for (const service of this.serviceFolders()) {
            const candidate = path.join(this.rulesRootFolderPath, service, this.safeRuleId, fileName);
            if (this.matchesRuleId(candidate)) return candidate;
        }
        this.failNotFound();
    }

    private serviceFolders(): string[] {
        return fs.readdirSync(this.rulesRootFolderPath, { withFileTypes: true }).filter(entry => entry.isDirectory()).map(entry => entry.name);
    }

    private matchesRuleId(filePath: string): boolean {
        if (!fs.existsSync(filePath)) return false;
        return this.readRequirements(filePath).ruleId === this.ruleId;
    }

    private serviceFromRequirementsPath(filePath: string): string {
        return path.basename(path.dirname(path.dirname(filePath)));
    }

    private descriptionFromRequirementsFile(filePath: string): string {
        return this.readRequirements(filePath).description;
    }

    private readRequirements(filePath: string): { ruleId: string; description: string } {
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }

    private failNotFound(): never {
        throw new RuleNotFoundError(`Rule '${this.ruleId}' not found. No requirements file matched under the security-matrix rules directory. To build a new rule, pass --service and --description, e.g. --rule ${this.ruleId} --service <service> --description '...'`);
    }
}
