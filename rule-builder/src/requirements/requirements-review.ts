import z from 'zod';
import { DraftRequirementSchema, RequirementsOutputSchema } from './requirements-schema.js';
import { OpusAgent } from '../shared/agents/opus-agent.js';

type Draft = z.infer<typeof RequirementsOutputSchema>;

export const ReviewSchema = z.object({
    drops: z.array(z.object({
        id: z.string().describe('The id of the scenario to remove'),
        reason: z.string().describe('Why this scenario does not belong in the list'),
        supersededBy: z.string().nullable().describe('The id of the scenario that already covers this configuration, or null when it is simply out of scope'),
    })).describe('Scenarios to remove — duplicates and configurations outside the rule'),
    revisions: z.array(DraftRequirementSchema).describe('Replacements for scenarios that need narrowing or correcting, each carrying the id of the scenario it replaces'),
    additions: z.array(DraftRequirementSchema).describe('Scenarios for states no existing entry covers, with ids continuing the sequence'),
});

export type Review = z.infer<typeof ReviewSchema>;

export class RequirementsReviewer {
    public async review(draft: Draft, ruleDescription: string): Promise<Review> {
        const agent = new OpusAgent({
            systemPrompt: SYSTEM_PROMPT,
            structuredOutputSchema: ReviewSchema,
        });

        const result = await agent.invoke(this.buildUserPrompt(draft, ruleDescription));
        return result.structuredOutput as Review;
    }

    private buildUserPrompt(draft: Draft, ruleDescription: string): string {
        return [
            `## Rule\n\n${ruleDescription}`,
            `## Decision Points\n\n${draft.decisionPoints.map(point => `${point.id}: ${point.description}`).join('\n')}`,
            `## Scenarios\n\n${draft.requirements.map(requirement => `${requirement.id} (${requirement.decisionPointId}): ${requirement.description}`).join('\n')}`,
            'Review this list.',
        ].join('\n\n');
    }
}

const SYSTEM_PROMPT = `You review a list of the configurations a security rule must reach a verdict on, with every entry in front of you at once. The agent that wrote it produced each entry in isolation, so the defects left are the ones only visible from the whole list.

No entry carries a verdict, and you must not add one. Whether a configuration is flagged or passed is decided after this review, by an agent that searches the AWS documentation. Your subject is the list's shape: what it covers, what it covers twice, and what it should not cover at all.

Each entry becomes a pair of generated unit tests and a branch of the rule's implementation, so a duplicate costs a redundant branch and a missing entry costs coverage nothing else will supply.

## What To Look For

**The same configuration described twice.** Two entries a single template would satisfy, or one that is a narrower case of another. Drop the redundant one, or revise the general one to exclude the narrow case where the narrow case is worth testing separately. Entries sharing a decision point are the likeliest place to find this.

**Compound entries.** An entry covering more than one configuration — "disabled or unspecified", "absent or empty" — produces one test for two configurations, so one of them goes untested. Revise it down to a single configuration and add an entry for the other.

**Scope drift.** A configuration the rule was never asked to judge, however sound a check it would make. The rule description is the authority.

**Verdicts smuggled into descriptions.** Words like "correctly", "properly", "insufficient" or "compliant" decide the answer before it has been researched. Revise them into plain descriptions of the configuration.

**Holes.** A state of a declared decision point that no entry covers. Work from what the value can be, not from a catalogue of scenario types: if a value has a threshold, both sides of it; if it is optional, its omission; if it is a collection, empty as well as populated; if it can come from an input resolved only at deployment, that too. Add what is missing.

## Removing An Entry Removes Coverage

The list you leave is what the rule will be tested against. So drop an entry only because it duplicates another or falls outside the rule — never because it looks hard to implement, hard to build a template for, or unlikely to appear in a real project. None of those is evidence about whether the configuration is one the scanner will meet.

Where two entries overlap and you must choose, keep the one stated in terms of the configuration itself rather than the one leaning on surrounding context, and keep the more precisely described of the two.

## Output

Return only changes. An entry you do not mention is kept exactly as written.

- A revision replaces the entry carrying the same id, in full, and follows the same rules as the original: one configuration, format-agnostic wording, no verdict.
- An addition takes the next unused REQ id and cites a declared decision point.
- A drop names the entry that supersedes it where one does, so the record shows where the coverage went.

Keep reasons short and in terms of the rule's purpose.
`;
