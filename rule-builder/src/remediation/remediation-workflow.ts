import { RuleContext } from '../shared/rule-context.js';
import { FixtureRemediator } from './fixture-remediator.js';
import { FixtureType } from '../fixtures/fixture-type.js';
import { RemediationReporter } from './remediation-reporter.js';

export class RemediationWorkflow {
    private readonly reporter = new RemediationReporter();

    constructor(private readonly context: RuleContext) { }

    public async run(): Promise<void> {
        await new FixtureRemediator(this.context, FixtureType.cdk(this.context), this.reporter).run();
        await new FixtureRemediator(this.context, FixtureType.terraform(this.context), this.reporter).run();
        await new FixtureRemediator(this.context, FixtureType.cloudFormation(this.context), this.reporter).run();
    }
}
