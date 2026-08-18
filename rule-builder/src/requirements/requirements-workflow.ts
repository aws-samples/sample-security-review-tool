import * as fs from 'node:fs';
import * as path from 'node:path';
import z from 'zod';
import { RuleContext } from '../shared/rule-context.js';
import type { DecisionPoint, RemovedRequirement, RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import { RequirementsAgent } from './requirements-agent.js';
import { ScenarioResolver, type Resolution } from './scenario-resolver.js';
import { FlagGapProbe } from './flag-gap-probe.js';
import { RequirementsReviewer, type Review } from './requirements-review.js';
import { RealizabilityProbe } from './realizability-probe.js';
import { ContradictionDetector, type Contradiction } from './requirements-contradictions.js';
import { auditDraft, auditResolved, decisionPointsWithoutFailure } from './requirements-audit.js';
import { DraftRequirementSchema, RequirementsOutputSchema } from './requirements-schema.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

const MAX_DRAFT_ATTEMPTS = 3;
const MAX_CONTRADICTION_ATTEMPTS = 3;

type RequirementsOutput = z.infer<typeof RequirementsOutputSchema>;
type DraftRequirement = z.infer<typeof DraftRequirementSchema>;

export interface RequirementsWorkflowOptions {
    regenerate?: boolean;
}

export class RequirementsWorkflow {
    private readonly logger = new RuleBuilderLogger();
    private removals: RemovedRequirement[] = [];
    private noFailingCases = new Map<string, string>();

    constructor(private readonly context: RuleContext) { }

    public async run(options: RequirementsWorkflowOptions = {}): Promise<RequirementsSpec> {
        if (this.hasCachedSpec(options)) return this.loadCachedSpec();
        this.removals = [];
        this.noFailingCases = new Map();

        const draft = await this.draftUntilSound();
        const resolved = await this.resolveAll(draft.requirements);
        const consistent = await this.settleContradictions(resolved);
        const covered = await this.coverFlagGaps(draft, consistent);
        const realizable = await this.dropUnrealizable(draft, covered);

        const spec = this.buildSpec(draft, realizable);
        this.reportRemainingGaps(spec);
        this.context.writeRequirements(spec);
        return spec;
    }

    private hasCachedSpec(options: RequirementsWorkflowOptions): boolean {
        return !options.regenerate && fs.existsSync(this.context.requirementsFilePath);
    }

    private loadCachedSpec(): RequirementsSpec {
        return JSON.parse(fs.readFileSync(this.context.requirementsFilePath, 'utf8'));
    }

    private async draftUntilSound(): Promise<RequirementsOutput> {
        let problems: string[] = [];

        for (let attempt = 1; attempt <= MAX_DRAFT_ATTEMPTS; attempt++) {
            const candidate = await this.applyReview(await this.draft(problems));

            problems = auditDraft(candidate);
            if (problems.length === 0) return candidate;

            this.logger.warning(`List rejected (attempt ${attempt} of ${MAX_DRAFT_ATTEMPTS})`);
            for (const problem of problems) this.logger.substep(problem);
        }

        throw new Error(`Scenario list for ${this.context.ruleId} still fails the audit after ${MAX_DRAFT_ATTEMPTS} attempts: ${problems.join('; ')}`);
    }

    private async draft(problems: string[]): Promise<RequirementsOutput> {
        return this.logger.task('listing scenarios', () => new RequirementsAgent().invoke(this.context.description, problems));
    }

    private async applyReview(draft: RequirementsOutput): Promise<RequirementsOutput> {
        const review = await this.logger.task('reviewing the list', () => new RequirementsReviewer().review(draft, this.context.description));

        const kept = this.applyDrops(draft.requirements, review);
        const revised = this.applyRevisions(kept, review);

        this.logger.step(`review: ${review.drops.length} dropped, ${review.revisions.length} revised, ${review.additions.length} added`);
        return { ...draft, requirements: [...revised, ...this.applyAdditions(revised, review)] };
    }

    private applyDrops(requirements: DraftRequirement[], review: Review): DraftRequirement[] {
        const drops = new Map(review.drops.map(drop => [drop.id, drop]));

        return requirements.filter(requirement => {
            const drop = drops.get(requirement.id);
            if (!drop) return true;

            this.logger.substep(`dropping ${requirement.id}: ${drop.reason}`);
            this.recordRemoval(requirement, drop.reason, drop.supersededBy ?? undefined);
            return false;
        });
    }

    private applyRevisions(requirements: DraftRequirement[], review: Review): DraftRequirement[] {
        const revisions = new Map(review.revisions.map(revision => [revision.id, revision]));
        return requirements.map(requirement => revisions.get(requirement.id) ?? requirement);
    }

    private applyAdditions(requirements: DraftRequirement[], review: Review): DraftRequirement[] {
        const revisedIds = new Set(requirements.map(requirement => requirement.id));
        const unmatchedRevisions = review.revisions.filter(revision => !revisedIds.has(revision.id));

        const nextId = this.idsAfter(requirements);
        return [...unmatchedRevisions, ...review.additions].map(addition => ({ ...addition, id: nextId() }));
    }

    /** Ids continue from the highest already in use, so a scenario added late never reuses one. */
    private idsAfter(requirements: DraftRequirement[]): () => string {
        let highest = requirements.reduce((max, requirement) => Math.max(max, Number(requirement.id.replace(/\D/g, '')) || 0), 0);
        return () => `REQ-${String(++highest).padStart(2, '0')}`;
    }

    private async resolveAll(scenarios: DraftRequirement[]): Promise<RuleRequirement[]> {
        this.logger.group(`researching ${scenarios.length} ${scenarios.length === 1 ? 'scenario' : 'scenarios'}`);
        const resolver = new ScenarioResolver();

        return Promise.all(scenarios.map(async scenario => {
            const resolution = await this.logger.concurrentTask(scenario.id, () => resolver.resolve(this.context.description, scenario));
            return this.merge(scenario, resolution);
        }));
    }

    private merge(scenario: DraftRequirement, resolution: Resolution): RuleRequirement {
        return {
            id: scenario.id,
            decisionPointId: scenario.decisionPointId,
            description: scenario.description,
            expectedBehavior: resolution.expectedBehavior,
            rationale: resolution.rationale,
            docReference: resolution.docReference,
            settledBy: resolution.settledBy,
            evidence: resolution.evidence,
        };
    }

    private async settleContradictions(requirements: RuleRequirement[]): Promise<RuleRequirement[]> {
        let settled = requirements;
        let contradictions = await this.detect(settled);

        for (let attempt = 1; contradictions.length > 0 && attempt <= MAX_CONTRADICTION_ATTEMPTS; attempt++) {
            this.logger.warning(`${contradictions.length} pair(s) demand opposite outcomes for one configuration`);
            settled = await this.resolveJointly(settled, contradictions);
            contradictions = await this.detect(settled);
        }

        if (contradictions.length === 0) return settled;

        throw new Error(`${this.context.ruleId} still contradicts itself after ${MAX_CONTRADICTION_ATTEMPTS} joint-resolution attempts: ${contradictions.map(pair => pair.ids.join(' vs ')).join(', ')}`);
    }

    private async detect(requirements: RuleRequirement[]): Promise<Contradiction[]> {
        const detector = new ContradictionDetector();
        return this.logger.task('checking for contradictions', () => detector.detect(requirements, this.context.description));
    }

    private async resolveJointly(requirements: RuleRequirement[], contradictions: Contradiction[]): Promise<RuleRequirement[]> {
        const resolver = new ScenarioResolver();
        const byId = new Map(requirements.map(requirement => [requirement.id, requirement]));

        for (const contradiction of contradictions) {
            const pair = contradiction.ids.map(id => byId.get(id)).filter((requirement): requirement is RuleRequirement => requirement !== undefined);
            if (pair.length < 2) continue;

            const joint = await this.logger.task(`deciding ${contradiction.ids.join(' and ')} together`, () =>
                resolver.resolveTogether(this.context.description, pair, contradiction.sharedInput));

            this.logger.step(`premise: ${joint.premise}`);
            for (const resolution of joint.resolutions) {
                const requirement = byId.get(resolution.requirementId);
                if (!requirement) continue;

                const description = resolution.description ?? requirement.description;
                byId.set(requirement.id, this.merge({ ...requirement, description }, resolution));
                if (description !== requirement.description) this.logger.substep(`${requirement.id} restated: ${description}`);
            }
        }

        return requirements.map(requirement => byId.get(requirement.id) ?? requirement);
    }

    private async coverFlagGaps(draft: RequirementsOutput, requirements: RuleRequirement[]): Promise<RuleRequirement[]> {
        const gaps = decisionPointsWithoutFailure(draft.decisionPoints, requirements);
        if (gaps.length === 0) return requirements;

        this.logger.group(`${gaps.length} decision point(s) with no failing scenario`);
        const probe = new FlagGapProbe();
        const nextId = this.idsAfter(requirements);

        const found = await Promise.all(gaps.map(async decisionPoint => {
            const covered = requirements.filter(requirement => requirement.decisionPointId === decisionPoint.id);
            const gap = await this.logger.concurrentTask(decisionPoint.id, () => probe.probe(this.context.description, decisionPoint, covered));
            return { decisionPoint, gap };
        }));

        const additions: RuleRequirement[] = [];
        for (const { decisionPoint, gap } of found) {
            if (!gap.flaggableConfiguration) {
                this.noFailingCases.set(decisionPoint.id, gap.reason);
                this.logger.step(`${decisionPoint.id}: no failing configuration — ${gap.reason}`);
                continue;
            }

            const scenario = { id: nextId(), decisionPointId: decisionPoint.id, description: gap.flaggableConfiguration };
            this.logger.step(`${decisionPoint.id} was missing ${scenario.id}: ${scenario.description}`);
            additions.push(this.merge(scenario, await this.researchAddition(scenario)));
        }

        return [...requirements, ...additions];
    }

    private async researchAddition(scenario: DraftRequirement): Promise<Resolution> {
        return this.logger.task(`researching ${scenario.id}`, () => new ScenarioResolver().resolve(this.context.description, scenario));
    }

    private async dropUnrealizable(draft: RequirementsOutput, requirements: RuleRequirement[]): Promise<RuleRequirement[]> {
        if (requirements.length === 0) return requirements;

        this.logger.group(`checking ${requirements.length} ${requirements.length === 1 ? 'scenario' : 'scenarios'} can be built`);
        const probe = new RealizabilityProbe(this.context, draft.cfnResources, draft.tfResources);
        const verdicts = new Map((await probe.probe(requirements)).map(verdict => [verdict.requirementId, verdict]));

        return requirements.filter(requirement => {
            const verdict = verdicts.get(requirement.id);
            if (!verdict || verdict.realizable) return true;

            this.logger.warning(`Removing ${requirement.id}: ${verdict.reason}`);
            this.recordRemoval(requirement, verdict.reason);
            return false;
        });
    }

    private recordRemoval(requirement: Pick<RuleRequirement, 'id' | 'description'>, reason: string, conflictedWith?: string): void {
        this.removals.push({
            id: requirement.id,
            description: requirement.description,
            reason,
            ...(conflictedWith && { conflictedWith }),
        });
    }

    private reportRemainingGaps(spec: RequirementsSpec): void {
        for (const problem of auditResolved(spec)) this.logger.warning(problem);
    }

    private buildSpec(draft: RequirementsOutput, requirements: RuleRequirement[]): RequirementsSpec {
        return {
            ruleId: this.context.ruleId,
            generatedAt: new Date().toISOString(),
            description: this.context.description,
            cfnResources: draft.cfnResources,
            tfResources: draft.tfResources,
            decisionPoints: draft.decisionPoints.map(decisionPoint => this.withCoverageNote(decisionPoint)),
            requirements,
            ...(this.removals.length > 0 && { removedRequirements: this.removals }),
        };
    }

    private withCoverageNote(decisionPoint: DecisionPoint): DecisionPoint {
        const noFailingCase = this.noFailingCases.get(decisionPoint.id);
        return noFailingCase ? { ...decisionPoint, noFailingCase } : decisionPoint;
    }

}
