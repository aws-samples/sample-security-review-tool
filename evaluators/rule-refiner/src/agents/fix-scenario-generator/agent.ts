import { Agent, BedrockModel } from '@strands-agents/sdk';
import z from 'zod';
import { SYSTEM_PROMPT, buildUserPrompt } from './prompt.js';
import { createAwsKnowledgeMcpClient } from '../../shared/aws-knowledge-mcp-client.js';

const FixScenarioSchema = z.object({
    scenarioId: z.string().describe('Short kebab-case identifier (e.g., "no-existing-log-bucket")'),
    description: z.string().describe('What this scenario tests'),
    templateSnippet: z.string().describe('Minimal template (YAML for CFN, JSON for Terraform) that triggers the violation in this starting state'),
    expectedFixBehavior: z.string().describe('What the fix should do in this scenario'),
});

const OutputSchema = z.object({
    scenarios: z.array(FixScenarioSchema).describe('2-4 distinct fix validation scenarios'),
});

export type FixScenario = z.infer<typeof FixScenarioSchema>;

export class FixScenarioGeneratorAgent {
    public async invoke(fixGuidance: string, ruleSource: string, applicableResourceTypes: string[], format: 'cfn' | 'terraform'): Promise<FixScenario[]> {
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new Agent({
                model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 16384 }),
                tools: [mcpClient],
                systemPrompt: SYSTEM_PROMPT,
                structuredOutputSchema: OutputSchema,
            });

            const userPrompt = buildUserPrompt(fixGuidance, ruleSource, applicableResourceTypes, format);
            const result = await agent.invoke(userPrompt);
            const output = result.structuredOutput as z.infer<typeof OutputSchema>;

            return output.scenarios;
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }
}
