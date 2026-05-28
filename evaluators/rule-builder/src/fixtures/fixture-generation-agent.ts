import { Agent, BedrockModel } from '@strands-agents/sdk';
import { RuleContext } from '../shared/rule-context.js';
import { AgentToolFactory } from '../implementation/agent-tools.js';
import { createAwsKnowledgeMcpClient } from '../shared/aws-knowledge-mcp-client.js';
import { FixtureGenerationPromptBuilder } from './fixture-generation-prompt.js';

export class FixtureGenerationAgent {
    private readonly promptBuilder: FixtureGenerationPromptBuilder;

    constructor(private readonly context: RuleContext) {
        this.promptBuilder = new FixtureGenerationPromptBuilder(context);
    }

    public async invoke(): Promise<void> {
        console.log(`\n==== Generating remediation fixture for ${this.context.ruleId} ====\n`);

        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new Agent({
                model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 16384 }),
                systemPrompt: this.promptBuilder.buildSystemPrompt(),
                tools: [
                    mcpClient,
                    AgentToolFactory.createWriteFileTool({ ensureDir: true }),
                    AgentToolFactory.createTscTool(this.context.cdkFixtureOutputFolderPath),
                ],
            });

            await agent.invoke(this.promptBuilder.buildUserPrompt());
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }
}
