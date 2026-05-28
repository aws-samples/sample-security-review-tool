import type { FixtureFormat, RuleEntry } from '../types/rule-catalog.js';

export class RuleCatalog {
    public static async find(checkId: string, fixtureFormat: FixtureFormat): Promise<RuleEntry> {
        const mod = await import('../../../../fix-validator/src/shared/rule-catalog/index.js' as string);
        return mod.RuleCatalog.find(checkId, fixtureFormat);
    }
}
