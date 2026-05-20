import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';
import { TestCreationAgent } from './test-creation-agent.js';
import { RuleImplementationAgent } from './rule-implementation-agent.js';

export class ImplementationWorkflow {
    private readonly testCreationAgent: TestCreationAgent;
    private readonly ruleImplementationAgent: RuleImplementationAgent;

    constructor(context: RuleContext) {
        this.testCreationAgent = new TestCreationAgent(context);
        this.ruleImplementationAgent = new RuleImplementationAgent(context);
    }

    public async implement(spec: RequirementsSpec): Promise<void> {
        for (const requirement of spec.requirements.filter(r => !r.implemented || !r.tested)) {
            if (requirement.implemented && requirement.tested) continue;

            await this.testCreationAgent.create(spec, requirement);
            await this.ruleImplementationAgent.implement(spec, requirement);
        }
    }
}
