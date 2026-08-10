import { RuleContext } from '../shared/rule-context.js';
import { FixtureGenerator } from './fixture-generator.js';
import { FixtureType } from './fixture-type.js';

export class FixtureWorkflow {
    constructor(private readonly context: RuleContext) { }

    public async run(): Promise<void> {
        const fixtureTypes = [FixtureType.cdk(this.context), FixtureType.terraform(this.context), FixtureType.cloudFormation(this.context)];
        await Promise.all(fixtureTypes.map(fixtureType => new FixtureGenerator(this.context, fixtureType).generate()));
    }
}
