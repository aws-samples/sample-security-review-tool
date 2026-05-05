import { FixtureFormat, RuleCatalog } from "../../shared/rule-catalog/index.js";

export class RuleFixtureAgent {
    public async invoke(ruleId: string, fixtureFormat: FixtureFormat): Promise<void> {
        const rule = await RuleCatalog.find(ruleId, fixtureFormat);

    }
}