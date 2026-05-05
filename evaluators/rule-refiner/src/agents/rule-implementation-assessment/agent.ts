import { Agent, BedrockModel, McpClient } from "@strands-agents/sdk";
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { SYSTEM_PROMPT, USER_PROMPT } from "./prompt.js";
import { RuleImplementationAssessmentOutputSchema } from "../types.js";
import { FixtureFormat, RuleCatalog } from "../../shared/rule-catalog/index.js";
import z from "zod";

export class RuleImplementationAssessmentAgent {

    public async invoke(ruleId: string, fixtureFormat: FixtureFormat): Promise<z.infer<typeof RuleImplementationAssessmentOutputSchema>> {
        await RuleCatalog.refresh();

        const awsKnowledgeMcpClient = new McpClient({ transport: new StreamableHTTPClientTransport(new URL('https://knowledge-mcp.global.api.aws')) });
        const rule = await RuleCatalog.find(ruleId, fixtureFormat);
        const userPrompt = USER_PROMPT.replace('{{RULE_IMPLEMENTATION}}', rule.ruleBody);

        try {
            const result = await this.getAgent(awsKnowledgeMcpClient).invoke(userPrompt);
            return result.structuredOutput as z.infer<typeof RuleImplementationAssessmentOutputSchema>;
        } finally {
            awsKnowledgeMcpClient.disconnect();
        }
    }

    private getAgent(awsKnowledgeMcpClient: McpClient): Agent {
        return new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
            tools: [awsKnowledgeMcpClient],
            systemPrompt: SYSTEM_PROMPT,
            structuredOutputSchema: RuleImplementationAssessmentOutputSchema
        });
    }
}