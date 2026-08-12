import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import { AgentToolFactory } from './agent-tools.js';
import { ImplementationResultSchema, type ImplementationResult } from './implementation-result-schema.js';
import { RuleImplementationPromptBuilder } from './rule-implementation-prompt.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';
import { OpusAgent } from '../shared/agents/opus-agent.js';

export class RuleImplementationAgent {
    private readonly promptBuilder: RuleImplementationPromptBuilder;
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly context: RuleContext) {
        this.promptBuilder = new RuleImplementationPromptBuilder(context);
    }

    public async implement(spec: RequirementsSpec, requirement: RuleRequirement): Promise<ImplementationResult> {
        const agent = new OpusAgent({
            systemPrompt: this.promptBuilder.buildSystemPrompt(),
            tools: [
                AgentToolFactory.createWriteFileTool(),
                AgentToolFactory.createFolderVitestTool(this.context.srtRootFolderPath, this.context.testsFolderPath),
                AgentToolFactory.createReadUnitTestTool(this.context.testsFolderPath),
            ],
            structuredOutputSchema: ImplementationResultSchema,
        });

        const result = await this.logger.task(`${requirement.id} implementation`, () => agent.invoke(this.promptBuilder.buildUserPrompt(spec, requirement)));
        return result.structuredOutput as ImplementationResult;
    }
}
