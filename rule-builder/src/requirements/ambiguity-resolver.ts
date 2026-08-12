import z from 'zod';
import { AmbiguityResolutionSchema } from './requirements-schema.js';
import { createAwsKnowledgeMcpClient } from '../shared/aws-knowledge-mcp-client.js';
import { OpusAgent } from '../shared/agents/opus-agent.js';

type Resolution = z.infer<typeof AmbiguityResolutionSchema>;

export class AmbiguityResolver {
    public async resolve(ruleDescription: string, scenario: string, question: string): Promise<Resolution> {
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new OpusAgent({
                tools: [mcpClient],
                systemPrompt: SYSTEM_PROMPT,
                structuredOutputSchema: AmbiguityResolutionSchema,
            });

            const result = await agent.invoke(this.buildUserPrompt(ruleDescription, scenario, question));
            return result.structuredOutput as Resolution;
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }

    private buildUserPrompt(ruleDescription: string, scenario: string, question: string): string {
        return `## Rule\n\n${ruleDescription}\n\n## Scenario\n\n${scenario}\n\n## Question\n\n${question}\n\nSettle this question.`;
    }
}

const SYSTEM_PROMPT = `You settle one ambiguity in the requirements specification for a security scanning rule.

The requirements agent could not determine whether the rule should flag or pass for a single scenario. Decide it, with evidence where evidence exists and with the safe default where it does not.

## Procedure

1. Search the AWS documentation for the security guidance governing this scenario.
2. If the documentation settles it, choose that behavior, cite the URL, and set settledBy to 'documentation'.
3. If nothing settles it, apply the default below, set docReference to null, and set settledBy to 'strict-default'.

## The Default: Flag

The two ways this rule can be wrong are not equally costly. A rule that passes a misconfigured resource ships permissive, and nothing in the output reveals the miss. A rule that flags a sound resource produces a finding a reviewer reads and dismisses. When the evidence does not decide, choose the behavior that flags.

Applied to the questions that recur:
- Partial coverage of a required scope → flag. A subset is not sufficient.
- A protective feature present but not demonstrably covering the assessed resource → flag.
- 'Explicitly disabled' and 'never configured' both leave the resource unprotected → both flag.

## The Exception: Unresolvable Values

When the deciding value depends on a condition that cannot be resolved at analysis time, the scanner does not know the configuration and therefore cannot assert non-compliance. Choose pass and set settledBy to 'intrinsic-exception'. This is the one case where the default inverts, and it applies only to genuine analysis-time unknowns — not to values that are merely absent, empty, or awkward to read.

## Two Sizes of Reason

Give the reason twice, because the two go to different readers.

The rationale is the full account — what you searched, what it said, why it decides this. It is filed as the evidence behind the decision, for a human reviewing the specification later.

The summary is one sentence stating the reason itself, readable without the rationale. It becomes the requirement's rationale, which is the only justification the later test-generation and implementation phases ever see. Write it as a reason ("parameter validation only checks parameters marked required, so this configuration enforces nothing"), never as a reference to a decision having been made ("settled by documentation").

## Do Not Manufacture Evidence

Set docReference only to a document you actually consulted and that actually addresses this scenario. If you did not find one, say so in the rationale and record the decision as a default. A resolution recorded honestly as a default gets reviewed; one dressed as a documented fact does not.
`;
