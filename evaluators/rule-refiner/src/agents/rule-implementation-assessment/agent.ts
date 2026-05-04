import { Agent, McpClient } from "@strands-agents/sdk";
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { SYSTEM_PROMPT, USER_PROMPT } from "./prompt.js";
import { RuleImplementationAssessmentOutputSchema } from "../types.js";
import { RuleCatalog } from "../../shared/rule-catalog/index.js";
import z from "zod";

export class RuleImplementationAssessmentAgent {
    private readonly awsKnowledgeMcpClient = new McpClient({ transport: new StreamableHTTPClientTransport(new URL('https://knowledge-mcp.global.api.aws')) });

    public async invoke(ruleId: string): Promise<z.infer<typeof RuleImplementationAssessmentOutputSchema>> {
        await RuleCatalog.refresh();
        
        const rule = await RuleCatalog.find(ruleId);
        const userPrompt = USER_PROMPT.replace('{{RULE_IMPLEMENTATION}}', rule.ruleBody);
        const result = await this.getAgent().invoke(userPrompt);

        return result.structuredOutput as z.infer<typeof RuleImplementationAssessmentOutputSchema>;
    }

    private getAgent(): Agent {
        return new Agent({
            model: 'global.anthropic.claude-opus-4-7',
            tools: [this.awsKnowledgeMcpClient],
            systemPrompt: SYSTEM_PROMPT,
            structuredOutputSchema: RuleImplementationAssessmentOutputSchema
        });
    }
}