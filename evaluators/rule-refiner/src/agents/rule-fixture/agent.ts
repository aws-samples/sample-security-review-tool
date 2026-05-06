import { Agent, BedrockModel, McpClient } from '@strands-agents/sdk';
import { httpRequest } from '@strands-agents/sdk/vended-tools/http-request';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { getSystemPrompt, buildUserPrompt } from './prompt.js';
import { RuleFixtureOutputSchema } from '../types.js';
import { FixtureFormat, RuleCatalog } from '../../shared/rule-catalog/index.js';
import { extractVariants } from '../../shared/variant-extractor.js';
import z from 'zod';

export class RuleFixtureAgent {

    public async invoke(ruleId: string, fixtureFormat: FixtureFormat): Promise<z.infer<typeof RuleFixtureOutputSchema>> {
        await RuleCatalog.refresh();
        const rule = await RuleCatalog.find(ruleId, fixtureFormat);
        const variants = extractVariants(rule.ruleBody);

        const awsKnowledgeMcpClient = new McpClient({
            transport: new StreamableHTTPClientTransport(new URL('https://knowledge-mcp.global.api.aws')),
        });

        const userPrompt = buildUserPrompt(rule.ruleBody, rule.checkId, fixtureFormat, variants);

        try {
            const result = await this.getAgent(awsKnowledgeMcpClient, fixtureFormat).invoke(userPrompt);
            return result.structuredOutput as z.infer<typeof RuleFixtureOutputSchema>;
        } finally {
            awsKnowledgeMcpClient.disconnect();
        }
    }

    private getAgent(awsKnowledgeMcpClient: McpClient, fixtureFormat: FixtureFormat): Agent {
        return new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
            tools: [httpRequest, awsKnowledgeMcpClient],
            systemPrompt: getSystemPrompt(fixtureFormat),
            structuredOutputSchema: RuleFixtureOutputSchema,
        });
    }
}
