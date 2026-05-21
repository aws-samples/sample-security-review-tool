import * as fs from 'fs/promises';
import * as path from 'path';
import { Agent, BedrockModel } from '@strands-agents/sdk';
import { RuleContext } from '../shared/rule-context.js';
import { AgentToolFactory } from '../implementation/agent-tools.js';
import { RemediationUpdaterPromptBuilder } from './remediation-updater-prompt.js';
import { FixValidationResult } from './remediation-workflow.js';
import z from 'zod';

const RemediationSchema = z.object({
    remediationInstructions: z.string().describe('Security rule remediation instructions')
});

export class RemediationUpdaterAgent {
    private readonly promptBuilder: RemediationUpdaterPromptBuilder;

    constructor(private readonly context: RuleContext) {
        this.promptBuilder = new RemediationUpdaterPromptBuilder();
    }

    public async invoke(details: FixValidationResult): Promise<void> { 
        const agent = new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 16384 }),
            systemPrompt: this.promptBuilder.buildSystemPrompt(),
            tools: [AgentToolFactory.createWriteFileTool()],
            structuredOutputSchema: RemediationSchema
        });

        const fixtureContent = await fs.readFile(path.join(this.context.cdkFixtureFolderPath, 'fixture-stack.ts'), 'utf8');
        const userPrompt = this.promptBuilder.buildUserPrompt(details, fixtureContent);

        const result = await agent.invoke(userPrompt);
        const structuredOutput = result.structuredOutput as z.infer<typeof RemediationSchema>;

        const controlContent = await fs.readFile(this.context.ruleControlFilePath, 'utf8');
        const escapedInstructions = this.escapeForStringLiteral(structuredOutput.remediationInstructions);
        const updatedControlContent = controlContent.replace(details.targetIssue.fix || '', escapedInstructions);
        await fs.writeFile(this.context.ruleControlFilePath, updatedControlContent, 'utf8');
    }


    private escapeForStringLiteral(value: string): string {
        return value.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '\\r');
    }

    // public async update(result: ValidationCycleResult, fixtureContent: string): Promise<void> {
    //     const agent = new Agent({
    //         model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 16384 }),
    //         systemPrompt: this.promptBuilder.buildSystemPrompt(),
    //         tools: [AgentToolFactory.createWriteFileTool()],
    //     });

    //     await agent.invoke(this.promptBuilder.buildUserPrompt(result, fixtureContent));
    // }
}
