import z from 'zod';
import { RequirementsOutputSchema } from './requirements-schema.js';
import { SYSTEM_PROMPT, buildUserPrompt } from './requirements-prompt.js';
import { createAwsKnowledgeMcpClient } from '../shared/aws-knowledge-mcp-client.js';
import { OpusAgent } from '../shared/agents/opus-agent.js';

export class RequirementsAgent {
    public async invoke(description: string, problems: string[] = []): Promise<z.infer<typeof RequirementsOutputSchema>> {
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new OpusAgent({
                tools: [mcpClient],
                systemPrompt: SYSTEM_PROMPT,
                structuredOutputSchema: RequirementsOutputSchema,
            });

            const result = await agent.invoke(buildUserPrompt(description, problems));
            return result.structuredOutput as z.infer<typeof RequirementsOutputSchema>;
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }
}
