import type { CatalogFilter, RuleEntry } from './types.js';
import { loadSecurityMatrixRules } from './security-matrix-source.js';
import { loadCheckovRules } from './checkov-source.js';
import { loadBanditRules } from './bandit-source.js';
import { loadSemgrepRules } from './semgrep-source.js';

export type { RuleEntry, CatalogFilter, Scanner, FixtureFormat } from './types.js';

export class RuleCatalog {
    private rules: RuleEntry[] = [];

    constructor(private readonly srtRepoRoot: string) {}

    public async load(): Promise<void> {
        const securityMatrix = await loadSecurityMatrixRules(this.srtRepoRoot);
        const checkov = loadCheckovRules(this.srtRepoRoot);
        const bandit = loadBanditRules(this.srtRepoRoot);
        const semgrep = loadSemgrepRules(this.srtRepoRoot);
        this.rules = [...securityMatrix, ...checkov, ...bandit, ...semgrep];
    }

    public list(filter: CatalogFilter = {}): RuleEntry[] {
        return this.rules.filter(rule => this.matches(rule, filter));
    }

    public find(checkId: string): RuleEntry | undefined {
        return this.rules.find(rule => rule.checkId === checkId);
    }

    private matches(rule: RuleEntry, filter: CatalogFilter): boolean {
        if (filter.checkId && rule.checkId !== filter.checkId) return false;
        if (filter.scanner && rule.scanner !== filter.scanner) return false;
        if (filter.service && rule.service !== filter.service) return false;
        return true;
    }

    public get count(): number {
        return this.rules.length;
    }
}
