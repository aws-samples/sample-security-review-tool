import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import type { RequirementsSpec } from '../shared/types/requirements.js';
import { TestCreationAgent } from './test-creation-agent.js';
import { RuleImplementationAgent } from './rule-implementation-agent.js';

export class ImplementationWorkflow {
    private readonly testCreationAgent: TestCreationAgent;
    private readonly ruleImplementationAgent: RuleImplementationAgent;

    constructor(private readonly context: RuleContext) {
        this.testCreationAgent = new TestCreationAgent(context);
        this.ruleImplementationAgent = new RuleImplementationAgent(context);
    }

    public async run(spec: RequirementsSpec): Promise<void> {
        for (const requirement of spec.requirements) {
            const cfnTestFilePath = path.join(this.context.testsFolderPath, `${requirement.id}.cfn.test.ts`);

            if (fs.existsSync(cfnTestFilePath)) continue;

            await this.testCreationAgent.create(spec, requirement);
            await this.ruleImplementationAgent.implement(spec, requirement);
        }
    }
}
