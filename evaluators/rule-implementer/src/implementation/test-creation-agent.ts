import { Agent, BedrockModel } from '@strands-agents/sdk';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import { AgentToolFactory } from './agent-tools.js';
import { TestCreationPromptBuilder } from './test-creation-prompt.js';

export class TestCreationAgent {
    private readonly promptBuilder: TestCreationPromptBuilder;

    constructor(private readonly context: RuleContext) {
        this.promptBuilder = new TestCreationPromptBuilder(context);
    }

    public async create(spec: RequirementsSpec, requirement: RuleRequirement): Promise<void> {       
        console.log(`\n==== Creating unit tests for ${spec.ruleId} ${requirement.id} ====\n`);

        const agent = new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
            systemPrompt: this.promptBuilder.buildSystemPrompt(),
            tools: [
                AgentToolFactory.createWriteFileTool({ ensureDir: true }),
                AgentToolFactory.createSingleFileVitestTool(this.context.srtRootFolderPath),
            ],
        });

        await agent.invoke(this.promptBuilder.buildUserPrompt(spec, requirement));
    }
}
