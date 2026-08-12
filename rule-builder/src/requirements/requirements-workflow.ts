import * as fs from 'node:fs';
import * as path from 'node:path';
import z from 'zod';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import { RequirementsAgent } from './requirements-agent.js';
import { AmbiguityResolver } from './ambiguity-resolver.js';
import { AmbiguityResolutionSchema, DraftRequirementSchema, RequirementsOutputSchema } from './requirements-schema.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

const MAX_LOGGED_QUESTION = 90;

type RequirementsOutput = z.infer<typeof RequirementsOutputSchema>;
type DraftRequirement = z.infer<typeof DraftRequirementSchema>;
type Resolution = z.infer<typeof AmbiguityResolutionSchema>;

export interface RequirementsWorkflowOptions {
    regenerate?: boolean;
}

export class RequirementsWorkflow {
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly context: RuleContext) { }

    public async run(options: RequirementsWorkflowOptions = {}): Promise<RequirementsSpec> {
        if (this.hasCachedSpec(options)) return this.loadCachedSpec();

        const output = await this.logger.task('drafting requirements', () => new RequirementsAgent().invoke(this.context.description));
        const spec = this.buildSpec(output, await this.settleAll(output.requirements));
        this.persist(spec);
        return spec;
    }

    private hasCachedSpec(options: RequirementsWorkflowOptions): boolean {
        return !options.regenerate && fs.existsSync(this.context.requirementsFilePath);
    }

    private loadCachedSpec(): RequirementsSpec {
        return JSON.parse(fs.readFileSync(this.context.requirementsFilePath, 'utf8'));
    }

    private async settleAll(drafts: DraftRequirement[]): Promise<RuleRequirement[]> {
        const open = drafts.filter(draft => draft.ambiguity !== null).length;
        if (open > 0) this.logger.group(`settling ${open} ${open === 1 ? 'ambiguity' : 'ambiguities'}`);

        const resolver = new AmbiguityResolver();
        return Promise.all(drafts.map(draft => this.settle(draft, resolver)));
    }

    private async settle(draft: DraftRequirement, resolver: AmbiguityResolver): Promise<RuleRequirement> {
        if (draft.ambiguity === null) {
            const { ambiguity, ...decided } = draft;
            return decided;
        }

        const resolution = await resolver.resolve(this.context.description, draft.description, draft.ambiguity);
        this.logResolution(draft.id, draft.ambiguity, resolution);

        return {
            id: draft.id,
            description: draft.description,
            category: draft.category,
            expectedBehavior: resolution.chosenBehavior,
            rationale: resolution.summary,
            ambiguity: {
                question: draft.ambiguity,
                settledBy: resolution.settledBy,
                docReference: resolution.docReference,
                evidence: resolution.rationale,
            },
        };
    }

    private logResolution(id: string, question: string, resolution: Resolution): void {
        this.logger.step(`${id} ${this.shorten(question)} → ${resolution.chosenBehavior} (${resolution.settledBy})`);
    }

    private shorten(question: string): string {
        if (question.length <= MAX_LOGGED_QUESTION) return question;
        return `${question.slice(0, MAX_LOGGED_QUESTION - 1).trimEnd()}…`;
    }

    private buildSpec(output: RequirementsOutput, requirements: RuleRequirement[]): RequirementsSpec {
        return {
            ruleId: this.context.ruleId,
            generatedAt: new Date().toISOString(),
            description: this.context.description,
            cfnResources: output.cfnResources,
            tfResources: output.tfResources,
            requirements,
        };
    }

    private persist(spec: RequirementsSpec): void {
        fs.mkdirSync(path.dirname(this.context.requirementsFilePath), { recursive: true });
        fs.writeFileSync(this.context.requirementsFilePath, JSON.stringify(spec, null, 2));
    }
}
