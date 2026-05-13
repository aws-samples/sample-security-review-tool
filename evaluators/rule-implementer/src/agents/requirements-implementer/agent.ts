import * as fs from 'node:fs';
import * as path from 'node:path';
import { Agent, BedrockModel } from '@strands-agents/sdk';
import { SYSTEM_PROMPT, buildUserPrompt } from './prompt.js';
import { RuleCatalog } from '../../shared/rule-catalog/index.js';
import { srtRepoRoot } from '../../shared/fixture-paths.js';
import { createAwsKnowledgeMcpClient } from '../../shared/aws-knowledge-mcp-client.js';
import { createReadFileTool, createWriteFileTool } from './tools.js';
import type { RuleRequirement } from '../../shared/types/requirements.js';
import type { GeneratedFixture } from '../../shared/types/fixtures.js';
import type { ValidationResult } from '../../shared/types/validation.js';

export class RequirementImplementationAgent {
    public async invoke(ruleId: string, fixtureFormat: string, requirement: RuleRequirement, fixture: GeneratedFixture, allRequirementsSoFar: RuleRequirement[], regressions: ValidationResult[], allFixtures: Map<string, GeneratedFixture>, resolvedTemplate?: string): Promise<void> {
        await RuleCatalog.refresh();

        const rule = await RuleCatalog.find(ruleId, fixtureFormat as any);
        const ruleBody = fs.readFileSync(rule.sourceLocation, 'utf8');
        const rulesDir = path.join(srtRepoRoot(), 'src', 'assess', 'scanning', 'security-matrix', 'rules');

        const userPrompt = buildUserPrompt(ruleBody, rule.sourceLocation, requirement, fixture, regressions, allRequirementsSoFar, allFixtures, resolvedTemplate);
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new Agent({
                model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
                tools: [mcpClient, createReadFileTool(rulesDir), createWriteFileTool(rulesDir)],
                systemPrompt: SYSTEM_PROMPT,
            });

            await agent.invoke(userPrompt);
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }
}
