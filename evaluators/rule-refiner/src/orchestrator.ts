import * as path from 'node:path';
import { RuleCatalog } from './shared/rule-catalog/index.js';
import type { CatalogFilter, FixtureFormat, RuleEntry } from './shared/rule-catalog/index.js';
import { createAwsKnowledgeMcpClient } from './shared/aws-knowledge-mcp-client.js';
import { createRefinerAgent } from './agent-factory.js';
import { buildUserPrompt } from './prompts.js';
import { extractVariants } from './shared/variant-extractor.js';
import { fixtureDirFor } from './shared/fixture-paths.js';
import { ReportWriter } from './report/report-writer.js';
import type { RefinerSession, RefinerResult, FindingVariant } from './types.js';

const TIMEOUT_MS = 45 * 60 * 1000;

export interface OrchestratorOptions {
    filter?: CatalogFilter;
    formats?: FixtureFormat[];
    phase1Only?: boolean;
    phase2Only?: boolean;
}

export class Orchestrator {
    constructor(
        private readonly srtRepoRoot: string,
        private readonly reportsDir: string,
        private readonly fixturesRoot: string,
    ) {}

    public async run(options: OrchestratorOptions): Promise<{ markdownPath: string; jsonPath: string }> {
        const catalog = new RuleCatalog(this.srtRepoRoot);
        await catalog.load();
        const rules = catalog.list({ ...(options.filter ?? {}), scanner: 'security-matrix' });
        if (rules.length === 0) throw new Error('No security-matrix rules matched the given filter.');

        console.log(`Refining ${rules.length} rule(s).`);
        const results: RefinerResult[] = [];

        for (const rule of rules) {
            const formats = this.resolveFormats(rule, options.formats);
            for (const format of formats) {
                console.log(`\n  [${rule.checkId}/${format}] Starting...`);
                const result = await this.refineOne(rule, format, options);
                if (result) {
                    results.push(result);
                    const p1 = result.phase1.correctness;
                    const p2Pass = result.phase2.variantResults.every(v => v.effectiveness === 'HIGH');
                    console.log(`  [${rule.checkId}/${format}] Phase1=${p1} Phase2=${p2Pass ? 'PASS' : 'FAIL'}`);
                }
            }
        }

        const writer = new ReportWriter(this.reportsDir);
        return writer.write(results);
    }

    private async refineOne(
        rule: RuleEntry,
        format: FixtureFormat,
        options: OrchestratorOptions,
    ): Promise<RefinerResult | null> {
        const variants = extractVariants(rule.ruleBody ?? '');
        const fixtureDir = fixtureDirFor(this.fixturesRoot, rule.scanner, format, rule.checkId);

        const session: RefinerSession = {
            rule,
            format,
            variants,
            fixtureDir,
            srtRepoRoot: this.srtRepoRoot,
            fixturesRoot: this.fixturesRoot,
            preFixIssues: new Map(),
            originalRuleSource: null,
            result: null,
        };

        const mcpClient = createAwsKnowledgeMcpClient();
        try {
            const agent = createRefinerAgent(session, mcpClient);
            const userPrompt = buildUserPrompt(rule, format, variants, fixtureDir);

            await Promise.race([
                agent.invoke(userPrompt),
                timeout(TIMEOUT_MS),
            ]);
        } catch (error) {
            console.error(`  [${rule.checkId}/${format}] Agent error: ${(error as Error).message}`);
        } finally {
            await mcpClient.disconnect().catch(() => {});
        }

        if (!session.result) {
            console.error(`  [${rule.checkId}/${format}] Agent did not call submit_result.`);
        }
        return session.result;
    }

    private resolveFormats(rule: RuleEntry, requested?: FixtureFormat[]): FixtureFormat[] {
        if (requested && requested.length > 0) {
            return requested.filter(f => rule.applicableFormats.includes(f));
        }
        return rule.applicableFormats;
    }
}

function timeout(ms: number): Promise<never> {
    return new Promise((_, reject) => setTimeout(() => reject(new Error(`Agent timed out after ${ms}ms`)), ms));
}
