import z from 'zod';
import { JointResolutionSchema, ResolutionSchema } from './requirements-schema.js';
import { createAwsKnowledgeMcpClient } from '../shared/aws-knowledge-mcp-client.js';
import { OpusAgent } from '../shared/agents/opus-agent.js';

export type Resolution = z.infer<typeof ResolutionSchema>;
export type JointResolution = z.infer<typeof JointResolutionSchema>;

interface Scenario {
    id: string;
    description: string;
}

export class ScenarioResolver {
    public async resolve(ruleDescription: string, scenario: Scenario): Promise<Resolution> {
        return this.withDocs(ResolutionSchema, SYSTEM_PROMPT,
            `## Rule\n\n${ruleDescription}\n\n## Configuration\n\n${scenario.description}\n\nDecide what the rule owes this configuration.`);
    }

    public async resolveTogether(ruleDescription: string, scenarios: Scenario[], sharedInput: string): Promise<JointResolution> {
        const listed = scenarios.map(scenario => `${scenario.id}: ${scenario.description}`).join('\n');

        return this.withDocs(JointResolutionSchema, JOINT_SYSTEM_PROMPT,
            `## Rule\n\n${ruleDescription}\n\n## Configurations\n\n${listed}\n\n## Why They Cannot Be Decided Separately\n\nOne configuration satisfies both descriptions: ${sharedInput}\n\nAnswer the premise they share, then decide both from that answer.`);
    }

    private async withDocs<T extends z.ZodTypeAny>(schema: T, systemPrompt: string, userPrompt: string): Promise<z.infer<T>> {
        const mcpClient = createAwsKnowledgeMcpClient();

        try {
            const agent = new OpusAgent({ tools: [mcpClient], systemPrompt, structuredOutputSchema: schema });
            const result = await agent.invoke(userPrompt);
            return result.structuredOutput as z.infer<T>;
        } finally {
            await mcpClient.disconnect().catch(() => { });
        }
    }
}

const DECIDING_RULES = `## Judge The Configuration The Service Will Have

A rule is about the state a resource ends up in, not about which words appear in a template. So the question is always what the service actually does with the configuration described.

This matters most where a value is absent. An omitted setting is not an unconfigured resource: the service may apply a default, and that default is the configuration the resource will run with. Look it up.

- If the documented default satisfies the rule, the configuration satisfies the rule. Pass. A resource that is safe in production is not a finding because a human did not type the value.
- If the documented default breaches the rule, or the service applies no default and leaves the protection off, flag.

Search for the default rather than assuming there is or is not one, and cite what you find. "Not explicitly set" is not a reason on its own, and a rationale that concludes non-compliance from the mere absence of text is wrong unless the absent value's own default is unsafe.

## When Nothing Settles It

Where you searched and no documentation decides the verdict, choose flag, set docReference to null, and record settledBy as 'strict-default'.

A rule that passes a misconfigured resource ships permissive and nothing in the output reveals the miss; a rule that flags a sound resource produces a finding a reviewer reads and dismisses. That asymmetry only applies once the search has come up empty — it is a tie-break, not a shortcut past the documentation.

## The Exception: Values Not Known Until Deployment

When the deciding value comes from an input resolved at deployment time, the scanner does not know the configuration and cannot assert a breach. Choose pass and record settledBy as 'intrinsic-exception'.

This covers genuine analysis-time unknowns only, not values that are merely absent, empty, or awkward to read. And it does not apply when every possible value the input could take breaches the rule — then the outcome is known regardless of which one is chosen, so decide on the merits.

## Do Not Manufacture Evidence

Set docReference only to a document you actually consulted and that actually addresses this configuration. If you found nothing, say so and record the verdict as a default. A verdict recorded honestly as a default gets reviewed; one dressed as a documented fact does not.

## Two Sizes Of Reason

The evidence is the full account: what you searched, what it said, why it decides this. It is filed for a human reviewing the specification later.

The rationale is one sentence stating the reason itself, readable on its own. It is the only justification the later test-generation and implementation phases ever see, so write it as a reason ("an omitted cooldown runs at the service default of 300 seconds, which is above the threshold the rule sets"), never as a reference to this process ("settled by documentation").`;

const SYSTEM_PROMPT = `You decide what a security scanning rule owes one configuration: a finding, or nothing.

The agent before you listed the configurations this rule must judge and deliberately did not judge them, because a verdict reached without reading the documentation is a guess that later phases treat as fact. Requirements decided that way have been measured wrong roughly one time in seven — an invented default, a reason that argues one way and concludes the other.

## Procedure

1. Identify what the verdict turns on for this configuration.
2. Search the AWS documentation for what the service does with it — the default when the value is absent, the values the setting accepts, what the setting actually controls.
3. Decide, and record where the decision came from.

${DECIDING_RULES}
`;

const JOINT_SYSTEM_PROMPT = `You decide what a security scanning rule owes two configurations that cannot be judged separately, because one configuration satisfies both descriptions at once.

Deciding them independently is what produced the conflict: each verdict was defensible on its own, and together they demand opposite outcomes for the same input. So answer the question underneath them both first, then let both verdicts follow from that answer.

## Procedure

1. Name the premise the two share — the question whose answer moves both verdicts. It is usually a definition the rule leaves open, or what the service does when a value is absent.
2. Search the AWS documentation and answer it.
3. Decide both configurations from that answer. They may still differ, if the descriptions differ in some other way that the premise does not govern — but neither verdict may contradict the answer you just gave.

Return the premise and its answer, then one verdict per configuration.

${DECIDING_RULES}
`;
