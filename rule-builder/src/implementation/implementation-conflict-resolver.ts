import * as fs from 'node:fs';
import * as path from 'node:path';
import z from 'zod';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import type { ImplementationResult } from './implementation-result-schema.js';
import { OpusAgent } from '../shared/agents/opus-agent.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

const ConflictDecisionSchema = z.object({
    removedRequirementId: z.string().describe('The id of the requirement to remove (e.g. REQ-05)'),
    reason: z.string().describe('Why this requirement is the wrong one and the other is worth keeping'),
});

export class ImplementationConflictResolver {
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly context: RuleContext) {}

    public async resolve(conflict: ImplementationResult, spec: RequirementsSpec): Promise<string> {
        const current = this.findRequirement(spec, conflict.currentRequirementId!);
        const conflicting = this.findRequirement(spec, conflict.conflictingRequirementId!);

        this.printConflictSummary(current, conflicting, conflict.explanation!);
        const decision = await this.decideRemoval(current, conflicting, conflict.explanation!, spec);

        const removed = this.findRequirement(spec, decision.removedRequirementId);
        this.logger.warning(`Removing ${removed.id}: ${decision.reason}`);

        this.deleteTestFiles(removed.id);
        this.recordRemoval(spec, removed, this.otherOf(removed, current, conflicting), decision.reason);
        this.removeRequirementFromSpec(removed.id, spec);
        this.context.writeRequirements(spec);
        return removed.id;
    }

    private findRequirement(spec: RequirementsSpec, id: string): RuleRequirement {
        const requirement = spec.requirements.find(candidate => candidate.id === id);
        if (!requirement) throw new Error(`Cannot resolve conflict for ${this.context.ruleId}: ${id} is not in the requirements spec.`);
        return requirement;
    }

    private otherOf(removed: RuleRequirement, current: RuleRequirement, conflicting: RuleRequirement): RuleRequirement {
        return removed.id === current.id ? conflicting : current;
    }

    private printConflictSummary(current: RuleRequirement, conflicting: RuleRequirement, explanation: string): void {
        this.logger.warning(`Conflict detected between ${current.id} and ${conflicting.id}`);
        this.logger.step(explanation);
        this.logger.substep(`${current.id}: "${current.description}" → ${current.expectedBehavior}`);
        this.logger.substep(`${conflicting.id}: "${conflicting.description}" → ${conflicting.expectedBehavior}`);
    }

    private async decideRemoval(current: RuleRequirement, conflicting: RuleRequirement, explanation: string, spec: RequirementsSpec): Promise<z.infer<typeof ConflictDecisionSchema>> {
        const agent = new OpusAgent({
            systemPrompt: CONFLICT_SYSTEM_PROMPT,
            structuredOutputSchema: ConflictDecisionSchema,
        });

        const userPrompt = this.buildUserPrompt(current, conflicting, explanation, spec);
        const result = await this.logger.task(`resolving ${current.id} vs ${conflicting.id}`, () => agent.invoke(userPrompt));
        const decision = result.structuredOutput as z.infer<typeof ConflictDecisionSchema>;

        if (decision.removedRequirementId !== current.id && decision.removedRequirementId !== conflicting.id) {
            throw new Error(`Conflict resolution for ${this.context.ruleId} chose ${decision.removedRequirementId}, which is neither ${current.id} nor ${conflicting.id}.`);
        }

        return decision;
    }

    private buildUserPrompt(current: RuleRequirement, conflicting: RuleRequirement, explanation: string, spec: RequirementsSpec): string {
        return [
            `## Rule\n\n${spec.description}`,
            `## Why They Cannot Both Hold\n\n${explanation}`,
            `## ${current.id} → ${current.expectedBehavior}\n\n${current.description}\n\nRationale: ${current.rationale}`,
            `## ${conflicting.id} → ${conflicting.expectedBehavior}\n\n${conflicting.description}\n\nRationale: ${conflicting.rationale}`,
            'Choose which one to remove.',
        ].join('\n\n');
    }

    private recordRemoval(spec: RequirementsSpec, removed: RuleRequirement, kept: RuleRequirement, reason: string): void {
        spec.removedRequirements = [
            ...(spec.removedRequirements ?? []),
            {
                id: removed.id,
                description: removed.description,
                conflictedWith: kept.id,
                reason: `${reason} (research had settled it as: ${removed.rationale})`,
            },
        ];
    }

    private deleteTestFiles(requirementId: string): void {
        const cfnPath = path.join(this.context.testsFolderPath, `${requirementId}.cfn.test.ts`);
        const tfPath = path.join(this.context.testsFolderPath, `${requirementId}.tf.test.ts`);

        fs.rmSync(cfnPath, { force: true });
        fs.rmSync(tfPath, { force: true });

        this.logger.step(`Deleted test files for ${requirementId}`);
    }

    private removeRequirementFromSpec(requirementId: string, spec: RequirementsSpec): void {
        spec.requirements = spec.requirements.filter(r => r.id !== requirementId);
    }

}

const CONFLICT_SYSTEM_PROMPT = `Two requirements in a security rule's specification prescribe opposite outcomes for an input the implementation cannot tell apart. One of them must be removed, along with its tests. Choose which.

## What You Are Actually Deciding

Removing a requirement removes coverage. The requirement you keep is the behavior the rule will have; the one you drop is a scenario the rule will no longer be tested against. Decide which of the two describes the rule's real obligation.

## How To Choose

1. Which requirement follows from the rule's stated purpose? The rule description is the authority. A requirement that drifts from it — covering a scenario the rule was never meant to judge — is the one to remove.
2. Where both follow from the purpose, keep the one that flags. A rule that misses a real misconfiguration fails silently; one that over-reports fails visibly and gets corrected. Removing the 'flag' requirement to keep the 'pass' requirement makes the rule permissive, so it needs a reason from the rule's purpose, not convenience.
3. Ignore which one is harder to implement. That the implementation cannot currently distinguish the two inputs is the reason you were called; it is not evidence about which requirement is correct.

Give the reason in terms of the rule's purpose, so a reviewer reading the removal record later can tell whether the trade was sound.
`;
