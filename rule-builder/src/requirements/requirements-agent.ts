import z from 'zod';
import { RequirementsOutputSchema } from './requirements-schema.js';
import { RequirementsPromptBuilder } from './requirements-prompt.js';
import { createAwsKnowledgeMcpClient } from '../shared/aws-knowledge-mcp-client.js';
import { OpusAgent } from '../shared/agents/opus-agent.js';

export class RequirementsAgent {
    public async invoke(description: string): Promise<z.infer<typeof RequirementsOutputSchema>> {
        const promptBuilder = new RequirementsPromptBuilder();
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new OpusAgent({
                tools: [mcpClient],
                systemPrompt: promptBuilder.buildSystemPrompt(),
                structuredOutputSchema: RequirementsOutputSchema,
            });

            const result = await agent.invoke(promptBuilder.buildUserPrompt(description));
            return result.structuredOutput as z.infer<typeof RequirementsOutputSchema>;
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }

    public async invokeWithResolutions(description: string, resolvedDecisions: string[]): Promise<z.infer<typeof RequirementsOutputSchema>> {
        const promptBuilder = new RequirementsPromptBuilder();
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new OpusAgent({
                tools: [mcpClient],
                systemPrompt: promptBuilder.buildSystemPrompt(),
                structuredOutputSchema: RequirementsOutputSchema,
            });

            const userPrompt = promptBuilder.buildUserPrompt(description) + '\n\n## Resolved Decisions\n\nThe following ambiguities have been resolved by the user:\n' + resolvedDecisions.join('\n');
            const result = await agent.invoke(userPrompt);
            return result.structuredOutput as z.infer<typeof RequirementsOutputSchema>;
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }
}
