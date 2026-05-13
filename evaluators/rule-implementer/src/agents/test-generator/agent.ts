import { Agent, BedrockModel } from '@strands-agents/sdk';
import z from 'zod';
import { SYSTEM_PROMPT, buildUserPrompt } from './prompt.js';
import { validateFixtureStructure } from './structural-validator.js';
import { createAwsKnowledgeMcpClient } from '../../shared/aws-knowledge-mcp-client.js';
import type { RuleRequirement } from '../../shared/types/requirements.js';
import type { FixtureFormat, RuleEntry } from '../../shared/types/rule-catalog.js';
import type { GeneratedFixture, FixtureRegenerationContext } from '../../shared/types/fixtures.js';
import { RuleCatalog } from '../../shared/rule-catalog/index.js';

const MAX_STRUCTURAL_RETRIES = 2;

const OutputSchema = z.object({
    templateSnippet: z.string().describe('The minimal template snippet (YAML for CFN, JSON for Terraform)'),
    resourceTypes: z.array(z.string()).describe('All resource types present in the fixture'),
});

export class FixtureGeneratorAgent {
    public async invoke(requirement: RuleRequirement, ruleId: string, fixtureFormat: FixtureFormat, regenerationContext?: FixtureRegenerationContext): Promise<GeneratedFixture> {
        const rule = await RuleCatalog.find(ruleId, fixtureFormat);
        const applicableResourceTypes = rule.applicableResourceTypes ?? [];
        let lastResult: Omit<GeneratedFixture, 'generationAttempt'> | undefined;
        let lastError: string | undefined;

        for (let attempt = 1; attempt <= MAX_STRUCTURAL_RETRIES; attempt++) {
            const contextForAttempt = attempt === 1
                ? regenerationContext
                : this.buildRetryContext(requirement, lastResult!.templateSnippet, lastError!, regenerationContext);

            const result = await this.generate(requirement, rule, fixtureFormat, applicableResourceTypes, contextForAttempt);
            const validation = validateFixtureStructure(result.templateSnippet, applicableResourceTypes, fixtureFormat);

            if (validation.valid) {
                return { ...result, resourceTypes: validation.resourceTypes, generationAttempt: attempt };
            }

            lastResult = result;
            lastError = validation.error!;
            console.log(`    Fixture structural validation failed (attempt ${attempt}): ${validation.error}`);
        }

        return { ...lastResult!, generationAttempt: MAX_STRUCTURAL_RETRIES };
    }

    private async generate(requirement: RuleRequirement, rule: RuleEntry, fixtureFormat: FixtureFormat, applicableResourceTypes: string[], regenerationContext?: FixtureRegenerationContext): Promise<Omit<GeneratedFixture, 'generationAttempt'>> {
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new Agent({
                model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 16384 }),
                tools: [mcpClient],
                systemPrompt: SYSTEM_PROMPT,
                structuredOutputSchema: OutputSchema,
            });

            const userPrompt = buildUserPrompt(requirement, applicableResourceTypes, fixtureFormat, regenerationContext);
            const result = await agent.invoke(userPrompt);
            const output = result.structuredOutput as z.infer<typeof OutputSchema>;

            return {
                requirementId: requirement.id,
                templateSnippet: output.templateSnippet,
                resourceTypes: output.resourceTypes,
            };
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }

    private buildRetryContext(requirement: RuleRequirement, previousFixture: string, structuralError: string, originalContext?: FixtureRegenerationContext): FixtureRegenerationContext {
        return {
            previousFixture,
            failureDiagnostics: {
                ruleWasInvoked: false,
                matchedResourceTypes: [],
                templateResourceTypes: [],
                fixtureStructureValid: false,
                suggestedCause: 'fixture_wrong_structure',
                parseError: structuralError,
            },
        };
    }
}
