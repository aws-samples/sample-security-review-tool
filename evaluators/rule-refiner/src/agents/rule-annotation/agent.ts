import { Agent, BedrockModel } from '@strands-agents/sdk';
import { SYSTEM_PROMPT, USER_PROMPT } from './prompt.js';
import { RuleAnnotationOutputSchema } from '../types.js';
import { RuleCatalog } from '../../shared/rule-catalog/index.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import z from 'zod';

export class RuleAnnotationAgent {

    public async invoke(ruleId: string, limitations: string[]): Promise<void> {
        await RuleCatalog.refresh();
        const rule = await RuleCatalog.find(ruleId);
        const sourcePath = path.resolve(rule.sourceLocation);
        const currentSource = await fs.readFile(sourcePath, 'utf-8');

        const evaluationDate = new Date().toISOString().split('T')[0];
        const jsdocComment = await this.generateComment(currentSource, limitations, evaluationDate);

        const annotatedSource = this.insertJsdocComment(currentSource, jsdocComment);
        await fs.writeFile(sourcePath, annotatedSource, 'utf-8');
    }

    private async generateComment(ruleSource: string, limitations: string[], evaluationDate: string): Promise<string> {
        const limitationsText = limitations.length > 0
            ? limitations.map(l => `- ${l}`).join('\n')
            : '(none identified)';

        const userPrompt = USER_PROMPT
            .replace('{{RULE_SOURCE}}', ruleSource)
            .replace('{{LIMITATIONS}}', limitationsText)
            .replace('{{DATE}}', evaluationDate);

        const result = await this.getAgent().invoke(userPrompt);
        const output = result.structuredOutput as z.infer<typeof RuleAnnotationOutputSchema>;
        return output.jsdocComment;
    }

    private insertJsdocComment(source: string, jsdocComment: string): string {
        const existingJsdocPattern = /\/\*\*[\s\S]*?\*\/\s*(?=export\s+class\s)/;
        const cleanedSource = source.replace(existingJsdocPattern, '');

        const classPattern = /(export\s+class\s)/;
        const match = cleanedSource.match(classPattern);

        if (!match || match.index === undefined) {
            return jsdocComment + '\n' + cleanedSource;
        }

        const before = cleanedSource.slice(0, match.index).trimEnd();
        const after = cleanedSource.slice(match.index);

        return before + '\n' + jsdocComment + '\n' + after;
    }

    private getAgent(): Agent {
        return new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-sonnet-4-6', maxTokens: 4096 }),
            systemPrompt: SYSTEM_PROMPT,
            structuredOutputSchema: RuleAnnotationOutputSchema
        });
    }
}
