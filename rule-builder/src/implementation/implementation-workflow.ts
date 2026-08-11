import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import { ImplementationConflictResolver } from './implementation-conflict-resolver.js';
import { TestCreationAgent } from './test-creation-agent.js';
import { checkDiscrimination } from './test-discrimination-check.js';
import { RuleImplementationAgent } from './rule-implementation-agent.js';
import { RuleBuilderLogger } from '../shared/logging/rule-builder-logger.js';

const MAX_CONFLICT_ESCALATIONS = 3;

export class ImplementationWorkflow {
    private readonly testCreationAgent: TestCreationAgent;
    private readonly ruleImplementationAgent: RuleImplementationAgent;
    private readonly conflictResolver: ImplementationConflictResolver;
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly context: RuleContext) {
        this.testCreationAgent = new TestCreationAgent(context);
        this.ruleImplementationAgent = new RuleImplementationAgent(context);
        this.conflictResolver = new ImplementationConflictResolver(context);
    }

    public async run(spec: RequirementsSpec): Promise<void> {
        const attempted = new Set<string>();

        let requirement = this.nextUnimplemented(spec, attempted);
        while (requirement) {
            attempted.add(requirement.id);
            await this.testCreationAgent.create(spec, requirement);
            await this.implementWithConflictResolution(spec, requirement);
            this.warnIfTestsMissing(requirement);
            requirement = this.nextUnimplemented(spec, attempted);
        }
    }

    private nextUnimplemented(spec: RequirementsSpec, attempted: Set<string>): RuleRequirement | undefined {
        return spec.requirements.find(requirement => !attempted.has(requirement.id) && !this.isAlreadyImplemented(requirement));
    }

    private warnIfTestsMissing(requirement: RuleRequirement): void {
        if (this.isAlreadyImplemented(requirement)) {
            this.warnIfTestsDoNotDiscriminate(requirement);
            return;
        }
        const missing = this.testFileNames(requirement).filter(name => !fs.existsSync(path.join(this.context.testsFolderPath, name)));
        this.logger.warning(`${requirement.id} did not produce ${missing.join(' and ')}. The requirement is not covered.`);
    }

    private warnIfTestsDoNotDiscriminate(requirement: RuleRequirement): void {
        for (const name of this.testFileNames(requirement)) {
            const result = checkDiscrimination(path.join(this.context.testsFolderPath, name));
            if (result.discriminates) continue;
            this.logger.warning(`${requirement.id} ${name} does not discriminate: ${result.reason}. The requirement is not proven.`);
        }
    }

    private isAlreadyImplemented(requirement: RuleRequirement): boolean {
        return this.testFileNames(requirement).every(name => fs.existsSync(path.join(this.context.testsFolderPath, name)));
    }

    private testFileNames(requirement: RuleRequirement): string[] {
        return [`${requirement.id}.cfn.test.ts`, `${requirement.id}.tf.test.ts`];
    }

    private async implementWithConflictResolution(spec: RequirementsSpec, requirement: RuleRequirement): Promise<boolean> {
        for (let attempt = 0; attempt < MAX_CONFLICT_ESCALATIONS; attempt++) {
            const result = await this.ruleImplementationAgent.implement(spec, requirement);
            if (result.status === 'success') return false;

            const resolution = await this.conflictResolver.resolve(result, spec);
            if (resolution.removedRequirementId === requirement.id) return true;
        }

        this.logger.warning(`Max conflict escalations reached for ${requirement.id}. Skipping.`);
        return false;
    }
}
