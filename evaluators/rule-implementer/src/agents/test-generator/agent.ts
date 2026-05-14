import * as fs from 'node:fs';
import * as path from 'node:path';
import { Agent, BedrockModel } from '@strands-agents/sdk';
import { fileEditor } from '@strands-agents/sdk/vended-tools/file-editor';
import { SYSTEM_PROMPT, buildUserPrompt, buildRetryPrompt } from './prompt.js';
import { resolveTestPaths } from './paths.js';
import { typecheckGeneratedTest } from './typecheck.js';
import type { RuleRequirement } from '../../shared/types/requirements.js';

const MAX_TYPECHECK_RETRIES = 1;

export class TestGeneratorAgent {
    public async invoke(requirement: RuleRequirement, ruleId: string, service: string, format: 'cfn' | 'tf'): Promise<void> {
        const paths = resolveTestPaths(ruleId, service, requirement.id, format);
        const factoryPath = format === 'cfn' ? paths.cfnFactoryPath : paths.tfFactoryPath;

        if (!fs.existsSync(paths.controlPath)) {
            throw new Error(`Control file not found: ${paths.controlPath}. Run scaffold phase first.`);
        }
        if (!factoryPath || !fs.existsSync(factoryPath)) {
            throw new Error(`Adapter factory not found for ${format} in service ${service}. Run scaffold phase first.`);
        }

        fs.mkdirSync(path.dirname(paths.testPath), { recursive: true });

        const userPrompt = buildUserPrompt(paths.testPath, paths.controlPath, factoryPath, ruleId, service, format, requirement);
        await this.runAgent(userPrompt);

        const errors = typecheckGeneratedTest(paths.testPath);
        if (errors.length === 0) return;

        console.log(`    Typecheck failed for ${requirement.id} ${format}, retrying...`);
        const retryPrompt = buildRetryPrompt(userPrompt, errors);
        await this.runAgent(retryPrompt);

        const retryErrors = typecheckGeneratedTest(paths.testPath);
        if (retryErrors.length > 0) {
            console.log(`    WARNING: ${requirement.id} ${format} still has typecheck errors after retry`);
        }
    }

    private async runAgent(prompt: string): Promise<void> {
        const agent = new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 16384 }),
            tools: [fileEditor],
            systemPrompt: SYSTEM_PROMPT,
        });
        await agent.invoke(prompt);
    }
}
