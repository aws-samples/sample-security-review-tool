import { Agent, BedrockModel } from '@strands-agents/sdk';
import { RuleContext } from '../shared/rule-context.js';
import { AgentToolFactory } from '../implementation/agent-tools.js';
import { createAwsKnowledgeMcpClient } from '../shared/aws-knowledge-mcp-client.js';
import { FixtureGenerationPromptBuilder } from './fixture-generation-prompt.js';
import { FixtureType } from './fixture-type.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

export class FixtureGenerationAgent {
    private readonly promptBuilder: FixtureGenerationPromptBuilder;
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly context: RuleContext, private readonly fixtureType: FixtureType) {
        this.promptBuilder = new FixtureGenerationPromptBuilder(context, fixtureType);
    }

    public async invoke(): Promise<void> {
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new Agent({
                model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 16384 }),
                systemPrompt: this.promptBuilder.buildSystemPrompt(),
                tools: [
                    mcpClient,
                    AgentToolFactory.createWriteFileTool({ ensureDir: true }),
                    this.fixtureType.createValidationTool(),
                ],
            });

            await this.logger.agentBlock(`generating ${this.fixtureType.label} fixture for ${this.context.ruleId}`, () => agent.invoke(this.promptBuilder.buildUserPrompt()));
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }
}
