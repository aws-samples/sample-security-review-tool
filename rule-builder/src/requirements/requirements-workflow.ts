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

        for (let i = 0; i < MAX_RESOLUTION_ITERATIONS && this.hasUnresolvedAmbiguities(output); i++) {
            resolutions.push(...await this.resolveAmbiguities(output.ambiguities));
            output = await agent.invokeWithResolutions(this.context.description, resolutions.map(resolution => this.formatDecision(resolution)));
        }

        this.failIfUnresolved(output);
        return { output, resolutions };
    }

    private hasUnresolvedAmbiguities(output: RequirementsOutput): boolean {
        return output.ambiguities.length > 0;
    }

    // The build runs unattended, so an ambiguity that survives every round has nobody to notice a warning.
    private failIfUnresolved(output: RequirementsOutput): void {
        if (!this.hasUnresolvedAmbiguities(output)) return;

        const scenarios = output.ambiguities.map(ambiguity => `  - ${ambiguity.scenario}: ${ambiguity.question}`).join('\n');
        throw new Error(`${output.ambiguities.length} ambiguities remain unresolved after ${MAX_RESOLUTION_ITERATIONS} rounds. The rule description is too vague to specify:\n${scenarios}`);
    }

    private buildSpec(resolved: ResolvedRequirements): RequirementsSpec {
        return {
            ruleId: this.context.ruleId,
            generatedAt: new Date().toISOString(),
            description: this.context.description,
            cfnResources: resolved.output.cfnResources,
            tfResources: resolved.output.tfResources,
            requirements: resolved.output.requirements,
            awsDocReferences: resolved.output.awsDocReferences,
            resolutions: resolved.resolutions,
        };
    }

    private async resolveAmbiguities(ambiguities: z.infer<typeof AmbiguitySchema>[]): Promise<AmbiguityResolution[]> {
        const resolver = new AmbiguityResolver();
        const resolutions: AmbiguityResolution[] = [];

        for (const ambiguity of ambiguities) {
            const resolution = await resolver.resolve(this.context.description, ambiguity);
            this.logger.step(`${ambiguity.scenario} → ${resolution.chosenBehavior} (${resolution.settledBy})`);
            if (resolution.docReference) this.logger.substep(resolution.docReference);
            resolutions.push({ scenario: ambiguity.scenario, question: ambiguity.question, ...resolution });
        }

        return resolutions;
    }

    private formatDecision(resolution: AmbiguityResolution): string {
        return `- ${resolution.scenario}: should ${resolution.chosenBehavior}. Rationale: ${resolution.rationale}`;
    }

    private persist(spec: RequirementsSpec): void {
        fs.mkdirSync(path.dirname(this.context.requirementsFilePath), { recursive: true });
        fs.writeFileSync(this.context.requirementsFilePath, JSON.stringify(spec, null, 2));
    }
}
