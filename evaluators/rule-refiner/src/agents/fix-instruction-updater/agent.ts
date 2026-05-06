import { Agent, BedrockModel } from '@strands-agents/sdk';
import { SYSTEM_PROMPT, USER_PROMPT } from './prompt.js';
import { FixInstructionUpdaterOutputSchema } from '../types.js';
import type { FixInstructionValidationResult } from '../types.js';
import { FixtureFormat, RuleCatalog } from '../../shared/rule-catalog/index.js';
import type { FindingVariant } from '../../types.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import z from 'zod';

export class FixInstructionUpdaterAgent {

    public async invoke(
        ruleId: string,
        fixtureFormat: FixtureFormat,
        variant: FindingVariant,
        validationResult: FixInstructionValidationResult,
    ): Promise<void> {
        await RuleCatalog.refresh();
        const rule = await RuleCatalog.find(ruleId, fixtureFormat);

        const userPrompt = this.buildUserPrompt(variant.fixGuidance, validationResult, rule.ruleBody);
        const result = await this.getAgent().invoke(userPrompt);
        const output = result.structuredOutput as z.infer<typeof FixInstructionUpdaterOutputSchema>;

        await fs.writeFile(path.resolve(rule.sourceLocation), output.updatedSource, 'utf-8');
    }

    private buildUserPrompt(fixGuidance: string, validationResult: FixInstructionValidationResult, ruleSource: string): string {
        const failureDetails = [
            validationResult.failureDetails,
            validationResult.fixError ? `Fix error: ${validationResult.fixError}` : null,
            validationResult.newIssuesIntroduced.length > 0
                ? `New issues introduced: ${validationResult.newIssuesIntroduced.join(', ')}`
                : null,
        ].filter(Boolean).join('\n');

        return USER_PROMPT
            .replace('{{FIX_GUIDANCE}}', fixGuidance)
            .replace('{{FAILURE_DETAILS}}', failureDetails)
            .replace('{{RULE_SOURCE}}', ruleSource);
    }

    private getAgent(): Agent {
        return new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
            systemPrompt: SYSTEM_PROMPT,
            structuredOutputSchema: FixInstructionUpdaterOutputSchema,
        });
    }
}
