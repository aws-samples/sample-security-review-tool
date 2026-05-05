import { RuleCatalog } from "../../shared/rule-catalog/index.js";

export type FixtureType = 'cdk' | 'cloudformation';

export class RuleFixtureAgent {
    public async invoke(ruleId: string, fixtureType: FixtureType): Promise<void> {
        const rule = await RuleCatalog.find(ruleId);
        
    }
}