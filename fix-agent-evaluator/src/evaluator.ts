import * as path from 'node:path';
import { getBedrockClient } from '../../src/shared/ai/bedrock-client.js';
import { SrtLogger } from '../../src/shared/logging/srt-logger.js';
import type { FixRunRecord, ReviewVerdict } from './types.js';
import { SrtRunner } from './srt-runner.js';
import { ReviewerAgent } from './reviewer/reviewer-agent.js';
import { ReviewerTools } from './reviewer/tools.js';
import { ReportWriter } from './report/report-writer.js';
import { RuleSourceLocator } from './rule-source-locator.js';

/**
 * Top-level orchestrator for the fix agent evaluator.
 *
 * Steps:
 *   1. scan   — run SRT against the target project to populate issues.json.
 *   2. fix    — iterate every high-priority open finding, let the FixAgent
 *               generate and apply a fix, and capture the per-finding session
 *               from the SRT log plus a git diff.
 *   3. review — for each finding, run a read-only Bedrock agent that returns
 *               a structured verdict including a drop-in replacement for the
 *               rule's `fix` text when needed.
 *   4. report — write markdown + JSON into `reports/`.
 */
export class Evaluator {
    constructor(
        private readonly targetProjectPath: string,
        private readonly srtRepoRoot: string,
        private readonly reportsDir: string,
    ) {}

    public async evaluate(): Promise<{ markdownPath: string; jsonPath: string }> {
        const runner = new SrtRunner(this.targetProjectPath);
        await runner.initialize();

        console.log('Scanning target project...');
        await runner.scan();

        console.log('Generating and applying fixes for high-priority findings...');
        const records = await runner.fixAllHighFindings();
        console.log(`Completed ${records.length} fix runs.`);

        console.log('Reviewing each fix...');
        const verdicts = await this.reviewAll(records);

        const writer = new ReportWriter(this.reportsDir);
        return writer.write(records, verdicts);
    }

    private async reviewAll(records: FixRunRecord[]): Promise<ReviewVerdict[]> {
        if (records.length === 0) return [];

        const bedrockClient = getBedrockClient();
        const tools = new ReviewerTools(this.targetProjectPath);
        const reviewer = new ReviewerAgent(bedrockClient, tools);
        const locator = new RuleSourceLocator(this.srtRepoRoot);

        const verdicts: ReviewVerdict[] = [];
        for (const record of records) {
            const ruleSource = await locator.findRuleSource(record.issue.check_id ?? '');
            try {
                const verdict = await reviewer.review(record, ruleSource);
                verdicts.push(verdict);
            } catch (error) {
                SrtLogger.logError('Reviewer threw', error as Error, {
                    checkId: record.issue.check_id,
                    path: record.issue.path,
                });
            }
        }
        return verdicts;
    }
}
