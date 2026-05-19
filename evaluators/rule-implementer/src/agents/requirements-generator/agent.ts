import * as fs from 'node:fs';
import * as path from 'node:path';
import { Agent, BedrockModel } from '@strands-agents/sdk';
import { select, input } from '@inquirer/prompts';
import z from 'zod';
import { SYSTEM_PROMPT, buildUserPrompt } from './prompt.js';
import { createAwsKnowledgeMcpClient } from '../../shared/aws-knowledge-mcp-client.js';
import { RuleContext } from '../../shared/fixture-paths.js';
import type { RequirementsSpec } from '../../shared/types/requirements.js';

const CUSTOM_INTERPRETATION = -1;

const RequirementCategorySchema = z.enum([
    'ABSENT', 'WRONG_TARGET', 'DISABLED', 'PARTIAL_COVERAGE',
    'EXPLICIT_EXCLUSION', 'INTRINSIC_UNRESOLVABLE', 'MIXED_CONFIG',
    'EMPTY_COLLECTION', 'WILDCARD_MATCH', 'SPECIFIC_RESOURCE',
]);

const RuleRequirementSchema = z.object({
    id: z.string().describe('Requirement identifier (e.g., REQ-01)'),
    description: z.string().describe('Format-agnostic scenario description — no IaC property names, resource types, or intrinsic functions'),
    category: RequirementCategorySchema.describe('Scenario category from the mandatory list'),
    expectedBehavior: z.enum(['flag', 'pass']).describe('Whether the rule should fire (flag) or not (pass)'),
    rationale: z.string().describe('Why this expected behavior is correct, referencing AWS docs or rule semantics'),
    implemented: z.boolean().describe('Whether this requirement has been implemented'),
    tested: z.boolean().describe('Whether this requirement has been tested'),
});

const AmbiguityOptionSchema = z.object({
    label: z.string().describe('Short description of this interpretation'),
    expectedBehavior: z.enum(['flag', 'pass']).describe('What the rule should do under this interpretation'),
});

const AmbiguitySchema = z.object({
    scenario: z.string().describe('The ambiguous scenario'),
    question: z.string().describe('Question to present to a human for resolution'),
    options: z.array(AmbiguityOptionSchema).min(2).describe('Possible interpretations'),
});

const RequirementsOutputSchema = z.object({
    requirements: z.array(RuleRequirementSchema).min(1).describe('Complete requirements specification'),
    cfnResources: z.array(z.string()).describe('List of CloudFormation resource types that trigger the rule'),
    tfResources: z.array(z.string()).describe('List of Terraform resource types that trigger the rule'),
    ambiguities: z.array(AmbiguitySchema).describe('Scenarios where the expected behavior is genuinely ambiguous and requires human decision'),
    awsDocReferences: z.array(z.string()).describe('AWS documentation URLs consulted'),
});

export interface RequirementsGeneratorOptions {
    regenerate?: boolean;
}

export class RequirementsGeneratorAgent {
    public async invoke(context: RuleContext, options: RequirementsGeneratorOptions = {}): Promise<RequirementsSpec> {
        if (!options.regenerate && fs.existsSync(context.requirementsFilePath)) {
            const fileContent = fs.readFileSync(context.requirementsFilePath, 'utf8');
            return JSON.parse(fileContent);
        }

        const userPrompt = buildUserPrompt(context.description);
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new Agent({
                model: new BedrockModel({ modelId: 'global.anthropic.claude-opus-4-7', maxTokens: 32768 }),
                tools: [mcpClient],
                systemPrompt: SYSTEM_PROMPT,
                structuredOutputSchema: RequirementsOutputSchema,
            });

            let result = await agent.invoke(userPrompt);
            let output = result.structuredOutput as z.infer<typeof RequirementsOutputSchema>;

            if (output.ambiguities.length > 0) {
                const resolvedDecisions = await this.resolveAmbiguities(output.ambiguities);
                const resolvedPrompt = userPrompt + '\n\n## Resolved Decisions\n\nThe following ambiguities have been resolved by the user:\n' + resolvedDecisions.join('\n');
                result = await agent.invoke(resolvedPrompt);
                output = result.structuredOutput as z.infer<typeof RequirementsOutputSchema>;
            }

            const spec: RequirementsSpec = {
                ruleId: context.ruleId,
                generatedAt: new Date().toISOString(),
                description: context.description,
                cfnResources: output.cfnResources,
                tfResources: output.tfResources,
                requirements: output.requirements,
                awsDocReferences: output.awsDocReferences,
            };

            this.persist(spec, context);
            
            return spec;
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }

    private async resolveAmbiguities(ambiguities: z.infer<typeof AmbiguitySchema>[]): Promise<string[]> {
        const decisions: string[] = [];

        for (const ambiguity of ambiguities) {
            console.log(`\n  Ambiguity: ${ambiguity.scenario}`);

            const choices = [
                ...ambiguity.options.map((opt, i) => ({ value: i, name: `${opt.label} (→ ${opt.expectedBehavior})` })),
                { value: CUSTOM_INTERPRETATION, name: 'None of these — provide your own interpretation' },
            ];

            const answer = await select({ message: ambiguity.question, choices });

            if (answer === CUSTOM_INTERPRETATION) {
                decisions.push(await this.collectCustomInterpretation(ambiguity.scenario));
            } else {
                const chosen = ambiguity.options[answer];
                decisions.push(`- ${ambiguity.scenario}: should ${chosen.expectedBehavior}. Rationale: user chose "${chosen.label}".`);
            }
        }

        return decisions;
    }

    private async collectCustomInterpretation(scenario: string): Promise<string> {
        const description = await input({ message: 'Describe the correct interpretation:', validate: (v) => v.trim().length > 0 || 'Cannot be empty' });

        const behavior = await select<string | null>({ message: 'What should the expected behavior be?', choices: [
            { value: 'flag', name: 'Flag (rule should produce a finding)' },
            { value: 'pass', name: 'Pass (rule should return null)' },
            { value: null, name: 'Let Claude decide based on my description' },
        ]});

        if (behavior) {
            return `- ${scenario}: should ${behavior}. Rationale: user provided custom interpretation: "${description.trim()}".`;
        }
        return `- ${scenario}: user's interpretation: "${description.trim()}". Determine the correct expected behavior based on this description.`;
    }

    private persist(spec: RequirementsSpec, context: RuleContext): void {
        fs.mkdirSync(path.dirname(context.requirementsFilePath), { recursive: true });
        fs.writeFileSync(context.requirementsFilePath, JSON.stringify(spec, null, 2));
    }
}
