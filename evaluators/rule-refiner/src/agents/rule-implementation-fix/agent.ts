import { Agent } from '@strands-agents/sdk';
import { IssueSchema, RuleImplementationAssessmentOutputSchema, RuleImplementationFixOutputSchema } from '../types.js';
import { RETRY_PROMPT, SYSTEM_PROMPT, USER_PROMPT } from './prompt.js';
import { RuleEntry } from '../../types.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import { spawnSync } from 'child_process';
import z from 'zod';

export class RuleImplementationFixAgent {
    private readonly agent: Agent = new Agent({
        model: 'global.anthropic.claude-opus-4-7',
        systemPrompt: SYSTEM_PROMPT,
        structuredOutputSchema: RuleImplementationFixOutputSchema
    });

    public async invoke(rule: RuleEntry, issues: z.infer<typeof RuleImplementationAssessmentOutputSchema>): Promise<void> {
        for (const issue of issues.issues) {
            let retries = 0;
            let error: string | null = null;

            while (retries < 3) {
                await this.applyFixToSource(rule, issue, error);

                const validationResult = await this.validateFix();

                if (validationResult.isValid) break;

                error = validationResult.errorMessage;
                retries++;
            }
        }
    }

    private async applyFixToSource(rule: RuleEntry, issue: z.infer<typeof IssueSchema>, error: string | null): Promise<void> {

        const result = await this.agent.invoke(this.getUserPrompt(issue, rule.ruleBody, error));
        const structuredOutput = result.structuredOutput as z.infer<typeof RuleImplementationFixOutputSchema>;

        await fs.writeFile(path.resolve(rule.sourceLocation), structuredOutput.updatedSource, 'utf-8');
    }

    private getUserPrompt(issue: z.infer<typeof IssueSchema>, ruleImplementation: string, error: string | null): string {
        let prompt = USER_PROMPT.replace('{{ISSUE}}', `${issue.description} (Property: ${issue.property}, Documentation: ${issue.documentation})`);
        prompt = prompt.replace('{{RULE_IMPLEMENTATION}}', ruleImplementation);

        if (error) {
            const retryPrompt = RETRY_PROMPT.replace('{{ERROR}}', error);
            prompt += `\n\n${retryPrompt}`;
        }

        return prompt;
    }

    private async validateFix(): Promise<{ isValid: boolean, errorMessage: string | null }> {
        const tscResult = spawnSync('npx', ['tsc', '--noEmit', '--pretty'], { encoding: 'utf-8' });

        return tscResult.status == 0 ?
            { isValid: true, errorMessage: null } :
            { isValid: false, errorMessage: tscResult.stdout };
    }
}