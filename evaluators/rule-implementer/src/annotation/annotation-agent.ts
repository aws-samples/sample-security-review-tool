import { Agent, BedrockModel } from '@strands-agents/sdk';
import z from 'zod';
import { AnnotationPromptBuilder } from './annotation-prompt.js';

const RuleAnnotationOutputSchema = z.object({
    jsdocComment: z.string().describe('The complete JSDoc comment block (including /** and */) to place above the class declaration'),
});

export class AnnotationAgent {
    public async invoke(ruleSource: string, evaluationDate: string): Promise<string> {
        const promptBuilder = new AnnotationPromptBuilder();

        const agent = new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-sonnet-4-6', maxTokens: 4096 }),
            systemPrompt: promptBuilder.buildSystemPrompt(),
            structuredOutputSchema: RuleAnnotationOutputSchema,
        });

        const result = await agent.invoke(promptBuilder.buildUserPrompt(ruleSource, evaluationDate));
        const output = result.structuredOutput as z.infer<typeof RuleAnnotationOutputSchema>;
        return output.jsdocComment;
    }
}
