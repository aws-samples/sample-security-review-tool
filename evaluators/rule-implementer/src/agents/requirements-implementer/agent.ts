import * as fs from 'node:fs';
import { Agent, BedrockModel } from '@strands-agents/sdk';
import { fileEditor } from '@strands-agents/sdk/vended-tools/file-editor';
import { SYSTEM_PROMPT, buildUserPrompt } from './prompt.js';
import { createAwsKnowledgeMcpClient } from '../../shared/aws-knowledge-mcp-client.js';
import type { RuleRequirement } from '../../shared/types/requirements.js';
import type { RegressionInfo } from '../../shared/types/implementation.js';

export class RequirementImplementationAgent {
    public async invoke(ruleId: string, service: string, requirement: RuleRequirement, testFile: { path: string; content: string }, failureOutput: string, regressions: RegressionInfo[]): Promise<void> {
        //const ruleBody = fs.readFileSync(controlPath, 'utf8');

        //const userPrompt = buildUserPrompt(ruleBody, controlPath, requirement, testFile, failureOutput, regressions);
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new Agent({
                model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
                tools: [mcpClient, fileEditor],
                systemPrompt: SYSTEM_PROMPT,
            });

            //await agent.invoke(userPrompt);
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }
}
