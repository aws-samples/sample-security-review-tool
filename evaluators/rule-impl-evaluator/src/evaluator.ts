import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleCatalog } from '../../shared/rule-catalog/src/index.js';
import type { CatalogFilter, RuleEntry } from '../../shared/rule-catalog/src/index.js';
import { createAwsKnowledgeMcpClient } from './aws-knowledge-mcp-client.js';
import { RuleImplReviewer } from './reviewer-agent.js';
import { ReportWriter } from './report-writer.js';
import type { RuleImplVerdict } from './types.js';

export interface EvaluateOptions {
    filter?: CatalogFilter;
    changedOnly?: boolean;
    concurrency?: number;
}

export interface EvaluateResult {
    markdownPath: string;
    jsonPath: string;
    verdicts: RuleImplVerdict[];
}

/**
 * Orchestrates review of every security-matrix rule's detection logic.
 * Checkov / Bandit / Semgrep are out of scope — their detection logic is
 * owned upstream.
 */
export class RuleImplEvaluator {
    constructor(
        private readonly srtRepoRoot: string,
        private readonly reportsDir: string,
    ) {}

    public async evaluate(options: EvaluateOptions): Promise<EvaluateResult> {
        const rules = await this.selectRules(options);
        if (rules.length === 0) {
            throw new Error('No security-matrix rules matched the given filter.');
        }
        console.log(`Reviewing ${rules.length} security-matrix rule(s).`);

        const mcpClient = createAwsKnowledgeMcpClient();
        try {
            const reviewer = new RuleImplReviewer(mcpClient);
            const verdicts = await this.runWithConcurrency(
                rules,
                options.concurrency ?? 4,
                rule => this.reviewOne(reviewer, rule),
            );

            const writer = new ReportWriter(this.reportsDir);
            const { markdownPath, jsonPath } = await writer.write(verdicts);
            return { markdownPath, jsonPath, verdicts };
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }
    }

    private async selectRules(options: EvaluateOptions): Promise<RuleEntry[]> {
        const catalog = new RuleCatalog(this.srtRepoRoot);
        await catalog.load();
        const filter: CatalogFilter = { ...(options.filter ?? {}), scanner: 'security-matrix' };
        const rules = catalog.list(filter);
        if (!options.changedOnly) return rules;

        const priorHashes = this.loadPriorHashes();
        if (priorHashes.size === 0) {
            console.log('--changed requested but no prior report found; reviewing all rules.');
            return rules;
        }
        return rules.filter(rule => priorHashes.get(rule.checkId) !== rule.sourceHash);
    }

    private loadPriorHashes(): Map<string, string> {
        const hashes = new Map<string, string>();
        if (!fs.existsSync(this.reportsDir)) return hashes;
        const jsonReports = fs
            .readdirSync(this.reportsDir)
            .filter(file => file.startsWith('impl-review-') && file.endsWith('.json'))
            .sort();
        const latest = jsonReports[jsonReports.length - 1];
        if (!latest) return hashes;
        try {
            const payload = JSON.parse(fs.readFileSync(path.join(this.reportsDir, latest), 'utf8')) as RuleImplVerdict[];
            for (const verdict of payload) {
                if (verdict.checkId && verdict.ruleSourceHash) {
                    hashes.set(verdict.checkId, verdict.ruleSourceHash);
                }
            }
        } catch {
            // Ignore parse errors — treat as no prior state.
        }
        return hashes;
    }

    private async reviewOne(reviewer: RuleImplReviewer, rule: RuleEntry): Promise<RuleImplVerdict> {
        const verdict = await reviewer.review(rule);
        this.logVerdict(verdict);
        return verdict;
    }

    private logVerdict(verdict: RuleImplVerdict): void {
        const mark = verdict.correctness === 'CORRECT' ? 'OK' : verdict.correctness;
        const citations = verdict.awsDocCitations.length;
        const misses = verdict.missedCases.length;
        const fps = verdict.falsePositiveRisks.length;
        console.log(
            `  [${mark}] ${verdict.checkId} — citations=${citations} missed=${misses} false-positives=${fps}`,
        );
    }

    private async runWithConcurrency<T>(
        items: RuleEntry[],
        concurrency: number,
        worker: (item: RuleEntry) => Promise<T>,
    ): Promise<T[]> {
        const results: T[] = new Array(items.length);
        let nextIndex = 0;

        async function runWorker(): Promise<void> {
            while (true) {
                const index = nextIndex++;
                if (index >= items.length) return;
                results[index] = await worker(items[index]);
            }
        }

        const workerCount = Math.max(1, Math.min(concurrency, items.length));
        await Promise.all(Array.from({ length: workerCount }, runWorker));
        return results;
    }
}
