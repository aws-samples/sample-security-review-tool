import type { CatalogFilter, FixtureFormat, RuleEntry } from '../types/rule-catalog.js';
import { loadSecurityMatrixRules } from './security-matrix-source.js';
import { loadCheckovRules } from './checkov-source.js';
import { loadBanditRules } from './bandit-source.js';
import { loadSemgrepRules } from './semgrep-source.js';
import { srtRepoRoot as getSRTRoot } from '../fixture-paths.js';

export type { RuleEntry, CatalogFilter, Scanner, FixtureFormat } from '../types/rule-catalog.js';

export class RuleCatalog {
    private rules: RuleEntry[] = [];

    private static instance: RuleCatalog;

    private static async getInstance(): Promise<RuleCatalog> {
        if (!this.instance) await RuleCatalog.refresh();
        return RuleCatalog.instance;
    }

    public static async refresh(): Promise<void> {
        const catalog = new RuleCatalog();
        const srtRoot = getSRTRoot();
        const securityMatrix = await loadSecurityMatrixRules(srtRoot);
        const checkov = loadCheckovRules(srtRoot);
        const bandit = loadBanditRules(srtRoot);
        const semgrep = loadSemgrepRules(srtRoot);

        catalog.rules = [...securityMatrix, ...checkov, ...bandit, ...semgrep];

        RuleCatalog.instance = catalog;
    }

    public static async list(filter: CatalogFilter = {}): Promise<RuleEntry[]> {
        return (await RuleCatalog.getInstance()).rules.filter(rule => this.matches(rule, filter));
    }

    public static async find(checkId: string, fixtureFormat: FixtureFormat): Promise<RuleEntry> {
        const result = (await RuleCatalog.getInstance()).rules.find(rule => 
            rule.checkId === checkId && 
            rule.applicableFormats.includes(fixtureFormat)
        );

        if (!result) throw new Error(`Rule with checkId ${checkId} not found.`);

        return result;
    }

    private static async matches(rule: RuleEntry, filter: CatalogFilter): Promise<boolean> {
        if (filter.checkId && rule.checkId !== filter.checkId) return false;
        if (filter.scanner && rule.scanner !== filter.scanner) return false;
        if (filter.service && rule.service !== filter.service) return false;
        return true;
    }

    public static async count(): Promise<number> {
        return (await RuleCatalog.getInstance()).rules.length;
    }
}
