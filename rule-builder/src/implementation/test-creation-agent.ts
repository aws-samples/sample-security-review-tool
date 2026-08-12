import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import { AgentToolFactory } from './agent-tools.js';
import { TestCreationPromptBuilder } from './test-creation-prompt.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';
import { OpusAgent } from '../shared/agents/opus-agent.js';

export class TestCreationAgent {
    private readonly promptBuilder: TestCreationPromptBuilder;
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly context: RuleContext) {
        this.promptBuilder = new TestCreationPromptBuilder(context);
    }

    public async create(spec: RequirementsSpec, requirement: RuleRequirement, problems: string[] = []): Promise<void> {
        const agent = new OpusAgent({
            systemPrompt: this.promptBuilder.buildSystemPrompt(),
            tools: [
                AgentToolFactory.createWriteFileTool({ ensureDir: true }),
                AgentToolFactory.createSingleFileVitestTool(this.context.srtRootFolderPath),
                AgentToolFactory.createTestDiscriminationTool(this.context.ruleControlFilePath, this.context.srtRootFolderPath),
            ],
        });

        const label = problems.length > 0 ? `${requirement.id} tests (rewrite)` : `${requirement.id} tests`;

        await this.logger.task(label, () => agent.invoke(this.promptBuilder.buildUserPrompt(spec, requirement, problems)));
    }
}
