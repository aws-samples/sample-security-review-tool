import { RuleContext } from '../shared/rule-context.js';
import { FixtureRemediator } from './fixture-remediator.js';
import { FixtureType } from '../fixtures/fixture-type.js';
import { RemediationReporter } from './remediation-reporter.js';

export class RemediationWorkflow {
    private readonly reporter = new RemediationReporter();

    constructor(private readonly context: RuleContext) { }

    public async run(): Promise<string> {
        const fixtureTypes = [FixtureType.cdk(this.context), FixtureType.terraform(this.context), FixtureType.cloudFormation(this.context)];

        let remediated = 0;
        for (const fixtureType of fixtureTypes) {
            remediated += await new FixtureRemediator(this.context, fixtureType, this.reporter).run();
        }

        return `${remediated} findings remediated across ${fixtureTypes.length} fixtures`;
    }
}
