import { Agent, BedrockModel } from '@strands-agents/sdk';
import { SYSTEM_PROMPT, USER_PROMPT } from './prompt.js';
import { FixInstructionUpdaterOutputSchema } from '../types.js';
import type { FixInstructionValidationResult } from '../types.js';
import { FixtureFormat, RuleCatalog } from '../../shared/rule-catalog/index.js';
import type { FindingVariant } from '../../types.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import z from 'zod';

const FIXTURE_ENTRY_FILES = [
    'template.yaml',
    'lib/stack.ts',
    'main.tf',
];

export class FixInstructionUpdaterAgent {

    public async invoke(
        ruleId: string,
        fixtureFormat: FixtureFormat,
        variant: FindingVariant,
        validationResult: FixInstructionValidationResult,
        fixtureDir: string,
    ): Promise<void> {
        await RuleCatalog.refresh();
        const rule = await RuleCatalog.find(ruleId, fixtureFormat);
        const fixtureContent = await this.readFixtureContent(fixtureDir);

        const userPrompt = this.buildUserPrompt(variant.fixGuidance, validationResult, rule.ruleBody, fixtureContent);
        const result = await this.getAgent().invoke(userPrompt);
        const output = result.structuredOutput as z.infer<typeof FixInstructionUpdaterOutputSchema>;

        await fs.writeFile(path.resolve(rule.sourceLocation), output.updatedSource, 'utf-8');
    }

    private buildUserPrompt(
        fixGuidance: string,
        validationResult: FixInstructionValidationResult,
        ruleSource: string,
        fixtureContent: string,
    ): string {
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
            .replace('{{RULE_SOURCE}}', ruleSource)
            .replace('{{FIXTURE_CONTENT}}', fixtureContent);
    }

    private async readFixtureContent(fixtureDir: string): Promise<string> {
        const segments: string[] = [];

        for (const file of FIXTURE_ENTRY_FILES) {
            const filePath = path.join(fixtureDir, file);
            try {
                const content = await fs.readFile(filePath, 'utf-8');
                segments.push(`--- ${file} ---\n${content}`);
            } catch {
                // File doesn't exist for this format — skip
            }
        }

        return segments.length > 0 ? segments.join('\n\n') : '(no fixture files found)';
    }

    private getAgent(): Agent {
        return new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
            systemPrompt: SYSTEM_PROMPT,
            structuredOutputSchema: FixInstructionUpdaterOutputSchema,
        });
    }
}
