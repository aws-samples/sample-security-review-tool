import { Agent, McpClient } from "@strands-agents/sdk";
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { SYSTEM_PROMPT, USER_PROMPT } from "./prompt.js";
import { RuleImplementationAssessmentOutputSchema } from "../types.js";
import z from "zod";

export class RuleImplementationAssessmentAgent {
    private readonly awsKnowledgeMcpClient = new McpClient({ transport: new StreamableHTTPClientTransport(new URL('https://knowledge-mcp.global.api.aws')) });
    private readonly agent: Agent = new Agent({
        model: 'global.anthropic.claude-opus-4-7',
        tools: [this.awsKnowledgeMcpClient],
        systemPrompt: SYSTEM_PROMPT,
        structuredOutputSchema: RuleImplementationAssessmentOutputSchema
    });

    public async invoke(ruleImplementation: string): Promise<z.infer<typeof RuleImplementationAssessmentOutputSchema>> {
        const userPrompt = USER_PROMPT.replace('{{RULE_IMPLEMENTATION}}', ruleImplementation);
        const result = await this.agent.invoke(userPrompt);

        return result.structuredOutput as z.infer<typeof RuleImplementationAssessmentOutputSchema>;
    }
}