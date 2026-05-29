import { RuleContext } from '../shared/rule-context.js';
import { FixtureGenerator } from './fixture-generator.js';
import { FixtureType } from './fixture-type.js';

export class FixtureWorkflow {
    constructor(private readonly context: RuleContext) { }

    public async run(): Promise<void> {
        await new FixtureGenerator(this.context, FixtureType.cdk(this.context)).generate();
        await new FixtureGenerator(this.context, FixtureType.terraform(this.context)).generate();
        await new FixtureGenerator(this.context, FixtureType.cloudFormation(this.context)).generate();
    }
}
