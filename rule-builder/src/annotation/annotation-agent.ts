import z from 'zod';
import { AnnotationPromptBuilder } from './annotation-prompt.js';
import { SonnetAgent } from '../shared/agents/sonnet-agent.js';

const RuleAnnotationOutputSchema = z.object({
    jsdocComment: z.string().describe('The complete JSDoc comment block (including /** and */) to place above the class declaration'),
});

export class AnnotationAgent {
    public async invoke(ruleSource: string, evaluationDate: string): Promise<string> {
        const promptBuilder = new AnnotationPromptBuilder();

        const agent = new SonnetAgent({
            systemPrompt: promptBuilder.buildSystemPrompt(),
            structuredOutputSchema: RuleAnnotationOutputSchema,
        });

        const result = await agent.invoke(promptBuilder.buildUserPrompt(ruleSource, evaluationDate));
        const output = result.structuredOutput as z.infer<typeof RuleAnnotationOutputSchema>;
        return output.jsdocComment;
    }
}
