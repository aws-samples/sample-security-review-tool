import { Agent, BedrockModel } from '@strands-agents/sdk';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import { AgentToolFactory } from './agent-tools.js';
import { ImplementationResultSchema, type ImplementationResult } from './implementation-result-schema.js';
import { RuleImplementationPromptBuilder } from './rule-implementation-prompt.js';

export class RuleImplementationAgent {
    private readonly promptBuilder: RuleImplementationPromptBuilder;

    constructor(private readonly context: RuleContext) {
        this.promptBuilder = new RuleImplementationPromptBuilder(context);
    }

    public async implement(spec: RequirementsSpec, requirement: RuleRequirement): Promise<ImplementationResult> {
        console.log(`\n==== Implementing ${spec.ruleId} ${requirement.id} ====\n`);

        const agent = new Agent({
            model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
            systemPrompt: this.promptBuilder.buildSystemPrompt(),
            tools: [
                AgentToolFactory.createWriteFileTool(),
                AgentToolFactory.createFolderVitestTool(this.context.srtRootFolderPath, this.context.testsFolderPath),
                AgentToolFactory.createReadUnitTestTool(this.context.testsFolderPath),
            ],
            structuredOutputSchema: ImplementationResultSchema,
        });

        const result = await agent.invoke(this.promptBuilder.buildUserPrompt(spec, requirement));
        return result.structuredOutput as ImplementationResult;
    }
}
