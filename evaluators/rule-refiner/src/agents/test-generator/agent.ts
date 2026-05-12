import { Agent, BedrockModel } from '@strands-agents/sdk';
import z from 'zod';
import { SYSTEM_PROMPT, buildUserPrompt } from './prompt.js';
import type { RuleRequirement } from '../../types/requirements.js';
import type { GeneratedFixture } from '../fixture-generator/types.js';

const OutputSchema = z.object({
    testFileContent: z.string().describe('The complete Vitest test file content'),
});

export class TestGeneratorAgent {
    public async invoke(ruleId: string, ruleClassName: string, ruleImportPath: string, applicableResourceTypes: string[], requirements: RuleRequirement[], fixtures: Map<string, GeneratedFixture>): Promise<string> {
        const agent = new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-sonnet-4-6-v1', maxTokens: 16384 }),
            systemPrompt: SYSTEM_PROMPT,
            structuredOutputSchema: OutputSchema,
        });

        const userPrompt = buildUserPrompt(ruleId, ruleClassName, ruleImportPath, applicableResourceTypes, requirements, fixtures);
        const result = await agent.invoke(userPrompt);
        const output = result.structuredOutput as z.infer<typeof OutputSchema>;

        return output.testFileContent;
    }
}
