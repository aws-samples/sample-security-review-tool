import * as fs from 'node:fs';
import * as path from 'node:path';
import { Agent, BedrockModel, McpClient } from "@strands-agents/sdk";
import { httpRequest } from "@strands-agents/sdk/vended-tools/http-request";
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { getSystemPrompt, USER_PROMPT } from "./prompt.js";
import { RuleImplementationAssessmentOutputSchema } from "../types.js";
import { FixtureFormat, RuleCatalog } from "../../shared/rule-catalog/index.js";
import { srtRepoRoot } from "../../shared/fixture-paths.js";
import z from "zod";

export class RuleImplementationAssessmentAgent {

    public async invoke(ruleId: string, fixtureFormat: FixtureFormat): Promise<z.infer<typeof RuleImplementationAssessmentOutputSchema>> {
        await RuleCatalog.refresh();

        const awsKnowledgeMcpClient = new McpClient({ transport: new StreamableHTTPClientTransport(new URL('https://knowledge-mcp.global.api.aws')) });
        const rule = await RuleCatalog.find(ruleId, fixtureFormat);
        console.log(`Rule: ${rule.applicableFormats.join(', ')} rule for ${rule.checkId}`);
        const pipelineContext = this.readPipelineContext(fixtureFormat);
        const userPrompt = USER_PROMPT
            .replace('{{RULE_IMPLEMENTATION}}', rule.ruleBody)
            .replace('{{PIPELINE_CONTEXT}}', pipelineContext);

        try {
            const result = await this.getAgent(awsKnowledgeMcpClient, fixtureFormat).invoke(userPrompt);
            return result.structuredOutput as z.infer<typeof RuleImplementationAssessmentOutputSchema>;
        } finally {
            awsKnowledgeMcpClient.disconnect();
       }
    }

    private getAgent(awsKnowledgeMcpClient: McpClient, fixtureFormat: FixtureFormat): Agent {
        return new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
            tools: [httpRequest, awsKnowledgeMcpClient],
            systemPrompt: getSystemPrompt(fixtureFormat),
            structuredOutputSchema: RuleImplementationAssessmentOutputSchema
        });
    }

    private readPipelineContext(fixtureFormat: FixtureFormat): string {
        const scannerDir = path.join(srtRepoRoot(), 'src', 'assess', 'scanning', 'security-matrix');
        const engineSource = this.readFile(path.join(scannerDir, 'matrix-scanner-engine.ts'));

        if (fixtureFormat === 'terraform') {
            const planReaderSource = this.readFile(path.join(scannerDir, 'terraform-plan-reader.ts'));
            return planReaderSource + '\n' + engineSource;
        }

        const cfnUtilsSource = this.readFile(path.join(scannerDir, 'cfn-utils.ts'));
        return cfnUtilsSource + '\n' + engineSource;
    }

    private readFile(filePath: string): string {
        return fs.readFileSync(filePath, 'utf8');
    }
}