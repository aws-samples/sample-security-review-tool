import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import { FixtureType } from './fixture-type.js';

export class FixtureGenerationPromptBuilder {
    constructor(private readonly context: RuleContext, private readonly fixtureType: FixtureType) { }

    public buildSystemPrompt(): string {
        return this.fixtureType.systemPrompt;
    }

    public buildUserPrompt(): string {
        const controlSource = fs.readFileSync(this.context.ruleControlFilePath, 'utf8');
        const adapterBaseSource = fs.readFileSync(this.context.ruleAdapterBaseFilePath, 'utf8');
        const adapterFlavorSource = fs.readFileSync(this.fixtureType.adapterFilePath, 'utf8');
        const fixtureOutputPath = path.join(this.fixtureType.outputFolderPath, this.fixtureType.resourceFileName);

        return `Write a ${this.fixtureType.label} fixture that triggers all remediation scenarios for rule ${this.context.ruleId}.

Save the file to: ${fixtureOutputPath}

<source-files>
    <source-file path="${this.context.ruleControlFilePath}">
    ${controlSource}
    </source-file>
    <source-file path="${this.context.ruleAdapterBaseFilePath}">
    ${adapterBaseSource}
    </source-file>
    <source-file path="${this.fixtureType.adapterFilePath}">
    ${adapterFlavorSource}
    </source-file>
</source-files>`;
    }
}
