import { getBedrockClient } from '../../../src/shared/ai/bedrock-client.js';
import { SrtLogger } from '../../../src/shared/logging/srt-logger.js';
import type { FixRunRecord, RescanResult, ReviewVerdict } from './types.js';
import { SrtRunner } from './srt-runner.js';
import { ReviewerAgent } from './reviewer/reviewer-agent.js';
import { ReviewerTools } from './reviewer/tools.js';
import { ReportWriter } from './report/report-writer.js';
import { CoverageReportWriter } from './report/coverage-report-writer.js';
import { RuleSourceLocator } from './rule-source-locator.js';
import { GeneratorCoordinator } from './fixture-generator/generator-coordinator.js';
import { RescanChecker } from './rescan-checker.js';
import { RuleCatalog } from '../../shared/rule-catalog/src/index.js';
import type { CatalogFilter, FixtureFormat, RuleEntry, Scanner } from '../../shared/rule-catalog/src/index.js';

export interface FixtureModeOptions {
    filter?: CatalogFilter;
    formats?: FixtureFormat[];
    regenerate?: boolean;
    concurrency?: number;
}

export interface FixtureRunResult {
    rule: RuleEntry;
    format: FixtureFormat;
    ungeneratable: boolean;
    ungeneratableReason?: string;
    verdict?: ReviewVerdict;
    error?: string;
}

/**
 * Top-level orchestrator for the fix agent evaluator.
 *
 * Two modes:
 *   - Legacy target-project mode (one git repo supplied by the user).
 *   - Fixture mode: iterate every fixable rule from the catalog, generate a
 *     minimal fixture, scan → fix → rescan → review, and write a coverage
 *     report alongside the drilldown report.
 */
export class Evaluator {
    constructor(
        private readonly srtRepoRoot: string,
        private readonly reportsDir: string,
        private readonly fixturesRoot: string,
    ) {}

    public async evaluateProject(targetProjectPath: string): Promise<{ markdownPath: string; jsonPath: string }> {
        const runner = new SrtRunner(targetProjectPath);
        await runner.initialize();

        console.log('Scanning target project...');
        await runner.scan();

        console.log('Generating and applying fixes for high-priority findings...');
        const records = await runner.fixAllHighFindings();
        console.log(`Completed ${records.length} fix runs.`);

        console.log('Reviewing each fix...');
        const verdicts = await this.reviewAll(targetProjectPath, records, new Map());

        const writer = new ReportWriter(this.reportsDir);
        return writer.write(records, verdicts);
    }

    public async evaluateFixtures(options: FixtureModeOptions): Promise<{ markdownPath: string; jsonPath: string; coveragePath: string }> {
        const catalog = new RuleCatalog(this.srtRepoRoot);
        await catalog.load();
        const rules = catalog.list(options.filter ?? {});
        if (rules.length === 0) {
            throw new Error('No rules matched the given filter.');
        }
        console.log(`Evaluating ${rules.length} rule(s) across fixtures.`);

        await this.ensureInitialized();

        const generator = new GeneratorCoordinator(getBedrockClient(), this.fixturesRoot, catalog);
        const results: FixtureRunResult[] = [];

        for (const rule of rules) {
            const targetFormats = this.resolveFormats(rule, options.formats);
            for (const format of targetFormats) {
                const runResult = await this.evaluateOneFixture(rule, format, generator, options.regenerate);
                results.push(runResult);
                this.logFixtureOutcome(rule, format, runResult);
            }
        }

        const records = results.filter((r): r is FixtureRunResult & { verdict: ReviewVerdict } => Boolean(r.verdict));
        const verdicts = records.map(r => r.verdict);
        const writer = new ReportWriter(this.reportsDir);
        const { markdownPath, jsonPath } = await writer.write(
            records.map(r => this.pseudoRecord(r)),
            verdicts,
        );

        const coverageWriter = new CoverageReportWriter(this.reportsDir);
        const coveragePath = await coverageWriter.write(rules, results);

        return { markdownPath, jsonPath, coveragePath };
    }

    private async evaluateOneFixture(
        rule: RuleEntry,
        format: FixtureFormat,
        generator: GeneratorCoordinator,
        regenerate: boolean | undefined,
    ): Promise<FixtureRunResult> {
        try {
            const fixture = await generator.generate(rule, format, { regenerate });
            if (fixture.ungeneratable) {
                return {
                    rule,
                    format,
                    ungeneratable: true,
                    ungeneratableReason: fixture.ungeneratableReason,
                };
            }

            const runner = new SrtRunner(fixture.fixtureDir);
            await runner.initialize();
            await runner.scan();

            const fixOutcome = await runner.fixIssueForRule(rule.checkId);
            if (!fixOutcome) {
                return {
                    rule,
                    format,
                    ungeneratable: false,
                    error: `fixIssueForRule returned null for ${rule.checkId} — fixture scan did not contain the target finding at fix time`,
                };
            }

            const rescan = await new RescanChecker().compare(
                fixture.fixtureDir,
                rule.checkId,
                rule.scanner,
                fixOutcome.preFixIssues,
            );

            const verdict = await this.reviewRecord(
                fixture.fixtureDir,
                rule.scanner,
                fixOutcome.record,
                rescan,
            );

            SrtRunner.resetFixture(fixture.fixtureDir);

            return { rule, format, ungeneratable: false, verdict };
        } catch (error) {
            return {
                rule,
                format,
                ungeneratable: false,
                error: (error as Error).message,
            };
        }
    }

    private async reviewRecord(
        projectPath: string,
        scanner: Scanner,
        record: FixRunRecord,
        rescan: RescanResult,
    ): Promise<ReviewVerdict> {
        const tools = new ReviewerTools(projectPath);
        const reviewer = new ReviewerAgent(getBedrockClient(), tools);
        const ruleSource = scanner === 'security-matrix'
            ? await new RuleSourceLocator(this.srtRepoRoot).findRuleSource(record.issue.check_id ?? '')
            : '';
        return reviewer.review(record, ruleSource, rescan);
    }

    private async reviewAll(
        targetProjectPath: string,
        records: FixRunRecord[],
        rescanByCheckId: Map<string, RescanResult>,
    ): Promise<ReviewVerdict[]> {
        if (records.length === 0) return [];

        const bedrockClient = getBedrockClient();
        const tools = new ReviewerTools(targetProjectPath);
        const reviewer = new ReviewerAgent(bedrockClient, tools);
        const locator = new RuleSourceLocator(this.srtRepoRoot);

        const verdicts: ReviewVerdict[] = [];
        for (const record of records) {
            const ruleSource = await locator.findRuleSource(record.issue.check_id ?? '');
            const rescan = rescanByCheckId.get(record.issue.check_id ?? '') ?? null;
            try {
                verdicts.push(await reviewer.review(record, ruleSource, rescan));
            } catch (error) {
                SrtLogger.logError('Reviewer threw', error as Error, {
                    checkId: record.issue.check_id,
                    path: record.issue.path,
                });
            }
        }
        return verdicts;
    }

    private resolveFormats(rule: RuleEntry, requested: FixtureFormat[] | undefined): FixtureFormat[] {
        if (!requested || requested.length === 0) return rule.applicableFormats;
        return requested.filter(format => rule.applicableFormats.includes(format));
    }

    private async ensureInitialized(): Promise<void> {
        // SrtLogger + BedrockConfig are process-global singletons. Initialize
        // via a throwaway runner so subsequent SrtRunners don't re-init.
        const dummy = new SrtRunner(this.srtRepoRoot);
        await dummy.initialize();
    }

    private logFixtureOutcome(rule: RuleEntry, format: FixtureFormat, result: FixtureRunResult): void {
        const id = `${rule.scanner}/${format}/${rule.checkId}`;
        if (result.ungeneratable) {
            console.log(`  [ungeneratable] ${id}: ${result.ungeneratableReason ?? 'unknown'}`);
            return;
        }
        if (result.error) {
            console.log(`  [error] ${id}: ${result.error}`);
            return;
        }
        const v = result.verdict!;
        const mark = v.overallPass ? 'PASS' : 'FAIL';
        console.log(`  [${mark}] ${id} — effectiveness=${v.effectiveness} efficiency=${v.efficiency} reasons=${v.failureReasons.join('|') || 'none'}`);
    }

    private pseudoRecord(result: FixtureRunResult & { verdict: ReviewVerdict }): FixRunRecord {
        // ReportWriter operates on FixRunRecord; the fixture-mode results only
        // carry verdicts (the underlying records were already consumed to
        // produce them). Build a minimal pseudo-record so the existing writer
        // keeps working during the transition to fixture-aware reports.
        return {
            issue: {
                source: result.rule.scanner,
                check_id: result.rule.checkId,
                priority: result.rule.priority,
                path: result.format,
                issue: result.rule.description,
                fix: result.rule.fixGuidance,
                resourceName: result.rule.applicableResourceTypes?.[0],
                status: 'Open',
            },
            fix: null,
            applied: true,
            session: {
                sessionId: null,
                turns: result.verdict.turns,
                stopReason: 'fixture-mode',
                applyFixAttempts: result.verdict.retries + 1,
                applyFixFailures: result.verdict.applyFixFailures,
                retries: result.verdict.retries,
                toolInvocations: [],
                finalComments: '',
                rawLogLines: [],
            },
            diff: '',
            durationMs: 0,
        };
    }
}
