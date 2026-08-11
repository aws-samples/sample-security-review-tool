import * as fs from 'node:fs';
import * as path from 'node:path';
import z from 'zod';
import { RuleContext } from '../shared/rule-context.js';
import type { AmbiguityResolution, RequirementsSpec } from '../shared/types/requirements.js';
import { RequirementsAgent } from './requirements-agent.js';
import { AmbiguityResolver } from './ambiguity-resolver.js';
import { AmbiguitySchema, RequirementsOutputSchema } from './requirements-schema.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

const MAX_RESOLUTION_ITERATIONS = 5;

type RequirementsOutput = z.infer<typeof RequirementsOutputSchema>;
type Ambiguity = z.infer<typeof AmbiguitySchema>;

interface ResolvedRequirements {
    output: RequirementsOutput;
    resolutions: AmbiguityResolution[];
}

export interface RequirementsWorkflowOptions {
    regenerate?: boolean;
}

export class RequirementsWorkflow {
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly context: RuleContext) { }

    public async run(options: RequirementsWorkflowOptions = {}): Promise<RequirementsSpec> {
        if (this.hasCachedSpec(options)) return this.loadCachedSpec();

        const agent = new RequirementsAgent();
        const resolved = await this.generateResolvedRequirements(agent);
        const spec = this.buildSpec(resolved);
        this.persist(spec);
        return spec;
    }

    private hasCachedSpec(options: RequirementsWorkflowOptions): boolean {
        return !options.regenerate && fs.existsSync(this.context.requirementsFilePath);
    }

    private loadCachedSpec(): RequirementsSpec {
        return JSON.parse(fs.readFileSync(this.context.requirementsFilePath, 'utf8'));
    }

    private async generateResolvedRequirements(agent: RequirementsAgent): Promise<ResolvedRequirements> {
        let output = await agent.invoke(this.context.description);
        const resolutions: AmbiguityResolution[] = [];

        for (let round = 0; round < MAX_RESOLUTION_ITERATIONS && this.hasUnresolvedAmbiguities(output); round++) {
            const pending = this.notYetResolved(output.ambiguities, resolutions);
            if (pending.length === 0) break;

            resolutions.push(...await this.resolveAmbiguities(pending));
            output = await agent.invokeWithResolutions(this.context.description, resolutions.map(resolution => this.formatDecision(resolution)));
            this.persist(this.buildSpec({ output, resolutions }));
        }

        this.warnIfUnresolved(output);
        return { output, resolutions };
    }

    private hasUnresolvedAmbiguities(output: RequirementsOutput): boolean {
        return output.ambiguities.length > 0;
    }

    // Matched on the scenario text, so a re-raised question that has been reworded still costs a
    // resolution. It stops the identical repeats, which are the ones that never converge.
    private notYetResolved(ambiguities: Ambiguity[], resolutions: AmbiguityResolution[]): Ambiguity[] {
        const settled = new Set(resolutions.map(resolution => resolution.scenario));
        return ambiguities.filter(ambiguity => !settled.has(ambiguity.scenario));
    }

    private warnIfUnresolved(output: RequirementsOutput): void {
        if (!this.hasUnresolvedAmbiguities(output)) return;

        this.logger.warning(`${output.ambiguities.length} ambiguities still open after ${MAX_RESOLUTION_ITERATIONS} rounds. Their requirements reflect the agent's own reading; the questions are recorded in ${this.context.requirementsFilePath} for review.`);
    }

    private buildSpec(resolved: ResolvedRequirements): RequirementsSpec {
        const stillOpen = resolved.output.ambiguities.map(ambiguity => ({ scenario: ambiguity.scenario, question: ambiguity.question }));

        return {
            ruleId: this.context.ruleId,
            generatedAt: new Date().toISOString(),
            description: this.context.description,
            cfnResources: resolved.output.cfnResources,
            tfResources: resolved.output.tfResources,
            requirements: resolved.output.requirements,
            awsDocReferences: resolved.output.awsDocReferences,
            resolutions: resolved.resolutions,
            ...(stillOpen.length > 0 && { unresolvedAmbiguities: stillOpen }),
        };
    }

    private async resolveAmbiguities(ambiguities: Ambiguity[]): Promise<AmbiguityResolution[]> {
        const resolver = new AmbiguityResolver();
        this.logger.group(`resolving ${ambiguities.length} ${ambiguities.length === 1 ? 'ambiguity' : 'ambiguities'}`);

        const resolutions = await Promise.all(ambiguities.map(async (ambiguity) => {
            const resolution = await resolver.resolve(this.context.description, ambiguity);
            return { scenario: ambiguity.scenario, question: ambiguity.question, ...resolution };
        }));

        for (const resolution of resolutions) {
            this.logger.step(`${resolution.scenario} → ${resolution.chosenBehavior} (${resolution.settledBy})`);
            if (resolution.docReference) this.logger.substep(resolution.docReference);
        }

        return resolutions;
    }

    // Only the decision goes back to the requirements agent. Feeding the resolver's full rationale in
    // gave it fresh distinctions to question, so each round invented finer edge cases instead of settling.
    private formatDecision(resolution: AmbiguityResolution): string {
        return `- ${resolution.scenario}: ${resolution.chosenBehavior}`;
    }

    private persist(spec: RequirementsSpec): void {
        fs.mkdirSync(path.dirname(this.context.requirementsFilePath), { recursive: true });
        fs.writeFileSync(this.context.requirementsFilePath, JSON.stringify(spec, null, 2));
    }
}
