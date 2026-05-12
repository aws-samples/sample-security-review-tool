import { Agent, BedrockModel } from '@strands-agents/sdk';
import z from 'zod';
import * as fs from 'fs/promises';
import * as path from 'path';
import { SYSTEM_PROMPT, buildUserPrompt } from './prompt.js';
import { FixtureFormat } from '../../types.js';
import { RuleCatalog } from '../../shared/rule-catalog/index.js';

const OutputSchema = z.object({
    description: z.string()
});

export class DescriptionRewriterAgent {
    public async invoke(ruleId: string, fixtureFormat: FixtureFormat): Promise<void> {
        const agent = new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-sonnet-4-6', maxTokens: 4096 }),
            tools: [],
            systemPrompt: SYSTEM_PROMPT,
            structuredOutputSchema: OutputSchema,
        });

        const rule = await RuleCatalog.find(ruleId, fixtureFormat);
        const userPrompt = buildUserPrompt(rule.description);
        const result = await agent.invoke(userPrompt);
        const output = result.structuredOutput as z.infer<typeof OutputSchema>;

        const sourcePath = path.resolve(rule.sourceLocation);
        const source = await fs.readFile(sourcePath, 'utf-8');
        const updatedSource = this.replaceDescription(source, rule.description, output.description);
        await fs.writeFile(sourcePath, updatedSource, 'utf-8');
    }

    private replaceDescription(source: string, oldDescription: string, newDescription: string): string {
        const escaped = oldDescription.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const pattern = new RegExp(`(super\\s*\\([^,]*,[^,]*,\\s*)(['"\`])${escaped}\\2`);
        return source.replace(pattern, `$1$2${newDescription}$2`);
    }
}
