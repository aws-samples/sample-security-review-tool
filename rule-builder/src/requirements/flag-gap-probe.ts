import z from 'zod';
import { createAwsKnowledgeMcpClient } from '../shared/aws-knowledge-mcp-client.js';
import { OpusAgent } from '../shared/agents/opus-agent.js';
import type { DecisionPoint, RuleRequirement } from '../shared/types/requirements.js';

const FlagGapSchema = z.object({
    flaggableConfiguration: z.string().nullable().describe('The configuration within this decision point that the rule must report, stated format-agnostically, or null when no configuration in its scope can breach the rule'),
    reason: z.string().describe('Why that configuration breaches the rule, or why no configuration in this decision point can'),
});

export type FlagGap = z.infer<typeof FlagGapSchema>;

export class FlagGapProbe {
    public async probe(ruleDescription: string, decisionPoint: DecisionPoint, covered: RuleRequirement[]): Promise<FlagGap> {
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new OpusAgent({ tools: [mcpClient], systemPrompt: SYSTEM_PROMPT, structuredOutputSchema: FlagGapSchema });
            const result = await agent.invoke(this.buildUserPrompt(ruleDescription, decisionPoint, covered));
            return result.structuredOutput as FlagGap;
        } finally {
            await mcpClient.disconnect().catch(() => { });
        }
    }

    private buildUserPrompt(ruleDescription: string, decisionPoint: DecisionPoint, covered: RuleRequirement[]): string {
        const listed = covered.map(requirement => `- ${requirement.id}: ${requirement.description}\n  Verdict: ${requirement.expectedBehavior} — ${requirement.rationale}`).join('\n');

        return [
            `## Rule\n\n${ruleDescription}`,
            `## Decision Point ${decisionPoint.id}\n\n${decisionPoint.description}`,
            `## Configurations Already Covered, All Passing\n\n${listed || '- none'}`,
            'Is there a configuration this decision point governs that the rule must report? Answer from the documentation.',
        ].join('\n\n');
    }
}

const SYSTEM_PROMPT = `A rule specification groups its configurations by the value each one turns on — its decision points. You are given one decision point where every configuration listed so far passes, and you decide whether a configuration exists that the rule would have to report.

## Why You Are Being Asked

A decision point whose configurations all pass may be complete, or it may be missing the case that matters. The two look identical in the finished specification, and the missing one is never noticed: the rule ships, its tests are green, and the configuration it should have caught was never written down.

## Your Answer

Name a configuration only if the rule genuinely owes it a finding.

- It must fall within this decision point's scope. A breach that belongs to a different decision point is not this one's gap.
- It must be a different configuration from those already covered, not a restatement of one.
- Search the documentation and decide what the service does with it, exactly as the verdicts above were reached. A configuration is only a breach if the state the service ends up in breaches the rule.

**Answering "no configuration here breaches" is a correct and expected outcome.** Some decision points have no failing case: where a service default already satisfies the rule, the absence of a value is compliant, and every configuration the decision point governs is sound. Say so and give the reason.

Do not invent a breach to fill the gap. A specification that forced every group to contain a failure produced scenarios written backwards from the requirement to have one — configurations nobody deploys, with rationales bent to justify them. A recorded "no failing case, because the documented default is safe" is worth more than a manufactured finding.

## Describing The Configuration

State it the way the covered configurations are stated: what the resource is configured with, in plain words. No CloudFormation or Terraform type names, property names, or intrinsic functions, and no verdict words ("compliant", "violates", "incorrectly") — the configuration is described, the verdict is the reason you give alongside it.
`;
