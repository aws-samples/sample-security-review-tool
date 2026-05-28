import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec, RuleRequirement } from '../shared/types/requirements.js';
import { ImplementationConflictResolver } from './implementation-conflict-resolver.js';
import { TestCreationAgent } from './test-creation-agent.js';
import { RuleImplementationAgent } from './rule-implementation-agent.js';

const MAX_CONFLICT_ESCALATIONS = 3;

export class ImplementationWorkflow {
    private readonly testCreationAgent: TestCreationAgent;
    private readonly ruleImplementationAgent: RuleImplementationAgent;
    private readonly conflictResolver: ImplementationConflictResolver;

    constructor(private readonly context: RuleContext) {
        this.testCreationAgent = new TestCreationAgent(context);
        this.ruleImplementationAgent = new RuleImplementationAgent(context);
        this.conflictResolver = new ImplementationConflictResolver(context);
    }

    public async run(spec: RequirementsSpec): Promise<void> {
        let i = 0;
        while (i < spec.requirements.length) {
            const requirement = spec.requirements[i];
            if (this.isAlreadyImplemented(requirement)) { i++; continue; }

            await this.testCreationAgent.create(spec, requirement);
            const wasRemoved = await this.implementWithConflictResolution(spec, requirement);
            if (!wasRemoved) i++;
        }
    }

    private isAlreadyImplemented(requirement: RuleRequirement): boolean {
        return fs.existsSync(path.join(this.context.testsFolderPath, `${requirement.id}.cfn.test.ts`));
    }

    private async implementWithConflictResolution(spec: RequirementsSpec, requirement: RuleRequirement): Promise<boolean> {
        for (let attempt = 0; attempt < MAX_CONFLICT_ESCALATIONS; attempt++) {
            const result = await this.ruleImplementationAgent.implement(spec, requirement);
            if (result.status === 'success') return false;

            const resolution = await this.conflictResolver.resolve(result, spec);
            if (resolution.removedRequirementId === requirement.id) return true;
        }

        console.log(`  ⚠ Max conflict escalations reached for ${requirement.id}. Skipping.`);
        return false;
    }
}
