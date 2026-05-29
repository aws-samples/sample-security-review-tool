import { RuleContext } from '../shared/rule-context.js';
import { FixtureRemediator } from './fixture-remediator.js';
import { FixtureType } from '../fixtures/fixture-type.js';

export class RemediationWorkflow {
    constructor(private readonly context: RuleContext) { }

    public async run(): Promise<void> {
        await new FixtureRemediator(this.context, FixtureType.cdk(this.context)).run();
        await new FixtureRemediator(this.context, FixtureType.terraform(this.context)).run();
    }
}
