import z from 'zod';
import { OpusAgent } from '../shared/agents/opus-agent.js';
import type { RuleRequirement } from '../shared/types/requirements.js';

const ContradictionsSchema = z.object({
    contradictions: z.array(z.object({
        firstId: z.string().describe('The id of one requirement in the pair'),
        secondId: z.string().describe('The id of the other requirement, the one demanding the opposite outcome'),
        sharedInput: z.string().describe('The one configuration that satisfies both descriptions at once'),
    })).describe('Empty when no two requirements share an input'),
});

export interface Contradiction {
    ids: [string, string];
    sharedInput: string;
}

export class ContradictionDetector {
    public async detect(requirements: RuleRequirement[], ruleDescription: string): Promise<Contradiction[]> {
        if (requirements.length < 2) return [];

        const agent = new OpusAgent({ systemPrompt: SYSTEM_PROMPT, structuredOutputSchema: ContradictionsSchema });
        const result = await agent.invoke(this.buildUserPrompt(requirements, ruleDescription));
        const reported = (result.structuredOutput as z.infer<typeof ContradictionsSchema>).contradictions;

        return this.keepOpposingPairs(reported, requirements);
    }

    /** The model can name an id that is not in the list, or pair two requirements that agree. Neither is a contradiction. */
    private keepOpposingPairs(reported: z.infer<typeof ContradictionsSchema>['contradictions'], requirements: RuleRequirement[]): Contradiction[] {
        const outcomes = new Map(requirements.map(requirement => [requirement.id, requirement.expectedBehavior]));

        return reported
            .filter(pair => outcomes.has(pair.firstId) && outcomes.has(pair.secondId))
            .filter(pair => outcomes.get(pair.firstId) !== outcomes.get(pair.secondId))
            .map(pair => ({ ids: [pair.firstId, pair.secondId] as [string, string], sharedInput: pair.sharedInput }));
    }

    private buildUserPrompt(requirements: RuleRequirement[], ruleDescription: string): string {
        const listed = requirements
            .map(requirement => `${requirement.id} → ${requirement.expectedBehavior} (${requirement.settledBy})\nConfiguration: ${requirement.description}\nReason: ${requirement.rationale}`)
            .join('\n\n');

        return `## Rule\n\n${ruleDescription}\n\n## Requirements\n\n${listed}\n\nWhich pairs, if any, share an input while demanding opposite outcomes?`;
    }
}

const SYSTEM_PROMPT = `You answer one question about a security rule's requirements specification: does a single configuration exist that satisfies two requirements demanding opposite verdicts?

Each requirement becomes a generated test and a branch of the rule's implementation. Where one configuration satisfies two requirements demanding opposite verdicts, the implementation cannot make both tests pass, and the rule ends up encoding whichever premise was written last.

## The Test To Apply

Compare each requirement against the ones carrying the opposite outcome. For each such pair, try to describe one concrete resource — a single template — that both descriptions truthfully describe. If you can, they share an input. Say what that configuration is.

Only pairs with opposite outcomes can contradict. Two requirements that both pass, or both flag, are never a contradiction however much they overlap.

This is a question about the described inputs, not about which outcome is correct. Do not decide which requirement is right; only report whether the same configuration falls under both.

## Compare The Scanner's Input, Not A Possible Deployed State

The input is the parsed infrastructure-as-code resource available during static analysis. Two requirements overlap only when the same template-time input satisfies both descriptions.

An unresolved value that might become X at deployment does not also satisfy a description saying the value is known to be X. Likewise, an unresolved choice between two configuration mechanisms does not overlap either known branch merely because deployment will eventually choose one. Unknown and known states are different scanner inputs.

## What Sharing An Input Looks Like

The commonest form is one description being a narrower case of another. "The setting is absent" and "the setting is absent while a related resource supplies it" both describe a resource whose setting is absent — the second just says more about the surroundings. If those two carry opposite outcomes, the rule has no way to be right.

Another form is two descriptions that name the same state in different words: "the value conveys no restriction" and "the value is empty" can be the same input.

## What Does NOT Count

**Complements are not overlaps.** A pair describing a value that meets a standard and a value that fails it is the specification working as intended. No single value is both positive and zero, both present and absent, both restrictive and permissive. Report nothing for those.

**Different resources are not overlaps.** Two descriptions about different resource kinds or different properties cannot share an input.

**Do not reason from likelihood.** That a configuration would be unusual, or that a template combining both is contrived, is irrelevant. Either one configuration satisfies both descriptions or none does.

Report each pair once. Return an empty list when nothing overlaps — that is the normal answer for a sound specification, and a false report costs real coverage.
`;
