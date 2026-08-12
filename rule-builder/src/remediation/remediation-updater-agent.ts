import * as fs from 'fs/promises';
import * as path from 'path';
import { RuleContext } from '../shared/rule-context.js';
import { AgentToolFactory } from '../implementation/agent-tools.js';
import { RemediationUpdaterPromptBuilder } from './remediation-updater-prompt.js';
import { FixValidationResult } from './fix-validation-result.js';
import { FixtureType } from '../fixtures/fixture-type.js';
import z from 'zod';
import { OpusAgent } from '../shared/agents/opus-agent.js';
import { RELATED_RULES_HEADING } from '../../../src/assess/scanning/security-matrix/controls/security-control.js';

const RemediationSchema = z.object({
    remediationInstructions: z.string().describe('Security rule remediation instructions')
});

export class RemediationUpdaterAgent {
    private readonly promptBuilder: RemediationUpdaterPromptBuilder;

    constructor(private readonly context: RuleContext, private readonly fixtureType: FixtureType) {
        this.promptBuilder = new RemediationUpdaterPromptBuilder();
    }

    public async invoke(details: FixValidationResult): Promise<string> {
        const agent = new OpusAgent({
            systemPrompt: this.promptBuilder.buildSystemPrompt(),
            tools: [AgentToolFactory.createWriteFileTool()],
            structuredOutputSchema: RemediationSchema
        });

        const failingIntent = this.failingIntentOf(details);
        const fixtureContent = await fs.readFile(path.join(this.fixtureType.outputFolderPath, this.fixtureType.resourceFileName), 'utf8');
        const controlSource = await fs.readFile(this.context.ruleControlFilePath, 'utf8');
        const adapterSource = await this.readAdapterSource();
        const userPrompt = this.promptBuilder.buildUserPrompt(details, failingIntent, fixtureContent, controlSource, adapterSource);

        const result = await agent.invoke(userPrompt);
        const structuredOutput = result.structuredOutput as z.infer<typeof RemediationSchema>;

        await this.replaceRemediationInControl(failingIntent, structuredOutput.remediationInstructions);

        return structuredOutput.remediationInstructions;
    }

    private failingIntentOf(details: FixValidationResult): string {
        const fix = details.targetIssue.fix;
        if (!fix) throw new Error(`Cannot update remediation for ${this.context.ruleId}: the failing finding has no fix text to replace.`);
        return fix.split(RELATED_RULES_HEADING)[0];
    }

    private async replaceRemediationInControl(failingIntent: string, newInstructions: string): Promise<void> {
        const controlContent = await fs.readFile(this.context.ruleControlFilePath, 'utf8');
        const existingIntent = this.escapeForStringLiteral(failingIntent);
        if (!controlContent.includes(existingIntent)) {
            throw new Error(`Cannot update remediation for ${this.context.ruleId}: the current fix text was not found in ${this.context.ruleControlFilePath}. The control may have been edited independently.`);
        }

        const replacement = this.escapeForStringLiteral(newInstructions);
        await fs.writeFile(this.context.ruleControlFilePath, controlContent.replaceAll(existingIntent, () => replacement), 'utf8');
    }

    private async readAdapterSource(): Promise<string> {
        const baseSource = await fs.readFile(this.context.ruleAdapterBaseFilePath, 'utf8');
        const flavorSource = await fs.readFile(this.fixtureType.adapterFilePath, 'utf8');
        return `${baseSource}\n\n${flavorSource}`;
    }

    private escapeForStringLiteral(value: string): string {
        return value.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '\\r');
    }
}
