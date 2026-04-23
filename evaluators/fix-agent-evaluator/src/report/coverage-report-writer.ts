import * as fs from 'node:fs';
import * as path from 'node:path';
import type { FixtureRunResult } from '../evaluator.js';
import type { RuleEntry, Scanner } from '../../../shared/rule-catalog/src/index.js';

interface ScannerBucket {
    total: number;
    pass: number;
    fail: number;
    ungeneratable: number;
    error: number;
}

/**
 * Maintainer-facing roll-up across every evaluated rule. Companion to the
 * existing per-rule drilldown in evaluation-*.md.
 */
export class CoverageReportWriter {
    constructor(private readonly reportsDir: string) {}

    public async write(rules: RuleEntry[], results: FixtureRunResult[]): Promise<string> {
        fs.mkdirSync(this.reportsDir, { recursive: true });
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const outputPath = path.join(this.reportsDir, `coverage-${timestamp}.md`);
        fs.writeFileSync(outputPath, this.render(rules, results), 'utf8');
        return outputPath;
    }

    private render(rules: RuleEntry[], results: FixtureRunResult[]): string {
        const buckets = this.bucketByScanner(results);
        const failures = results.filter(r => r.verdict && !r.verdict.overallPass);
        const ungeneratable = results.filter(r => r.ungeneratable);
        const errored = results.filter(r => r.error);

        const lines: string[] = [];
        lines.push(`# Fix Agent Evaluator Coverage Report`);
        lines.push('');
        lines.push(`Total rules in catalog: ${rules.length}`);
        lines.push(`Total evaluations (rule × format): ${results.length}`);
        lines.push('');

        lines.push(`## Pass rate by scanner`);
        lines.push('');
        lines.push(`| Scanner | Evaluated | Pass | Fail | Ungeneratable | Errored |`);
        lines.push(`| --- | ---: | ---: | ---: | ---: | ---: |`);
        for (const [scanner, bucket] of Object.entries(buckets)) {
            lines.push(`| ${scanner} | ${bucket.total} | ${bucket.pass} | ${bucket.fail} | ${bucket.ungeneratable} | ${bucket.error} |`);
        }
        lines.push('');

        if (failures.length > 0) {
            lines.push(`## Failing rules (${failures.length})`);
            lines.push('');
            lines.push(`| Check ID | Scanner | Format | Effectiveness | Efficiency | Rescan | Reasons |`);
            lines.push(`| --- | --- | --- | --- | --- | --- | --- |`);
            const sorted = [...failures].sort((a, b) => this.failurePriorityScore(b) - this.failurePriorityScore(a));
            for (const r of sorted) {
                const v = r.verdict!;
                const rescanSummary = this.rescanSummary(v.rescan);
                lines.push(
                    `| ${r.rule.checkId} | ${r.rule.scanner} | ${r.format} | ${v.effectiveness} | ${v.efficiency} | ${rescanSummary} | ${v.failureReasons.join(', ')} |`,
                );
            }
            lines.push('');

            lines.push(`### Suggested fix-guidance replacements`);
            lines.push('');
            for (const r of sorted) {
                const v = r.verdict!;
                if (!v.suggestedFixGuidance) continue;
                lines.push(`#### ${r.rule.checkId} (${r.format})`);
                lines.push('');
                lines.push(`Current:`);
                lines.push('```');
                lines.push(v.currentFixGuidance || '(none)');
                lines.push('```');
                lines.push(`Suggested:`);
                lines.push('```');
                lines.push(v.suggestedFixGuidance);
                lines.push('```');
                lines.push('');
            }
        }

        if (ungeneratable.length > 0) {
            lines.push(`## Ungeneratable rules (${ungeneratable.length})`);
            lines.push('');
            lines.push(`These rules need a hand-authored fixture or a fixture-generator prompt upgrade.`);
            lines.push('');
            lines.push(`| Check ID | Scanner | Format | Reason |`);
            lines.push(`| --- | --- | --- | --- |`);
            for (const r of ungeneratable) {
                lines.push(`| ${r.rule.checkId} | ${r.rule.scanner} | ${r.format} | ${r.ungeneratableReason ?? 'unknown'} |`);
            }
            lines.push('');
        }

        if (errored.length > 0) {
            lines.push(`## Errored evaluations (${errored.length})`);
            lines.push('');
            lines.push(`| Check ID | Scanner | Format | Error |`);
            lines.push(`| --- | --- | --- | --- |`);
            for (const r of errored) {
                lines.push(`| ${r.rule.checkId} | ${r.rule.scanner} | ${r.format} | ${r.error ?? ''} |`);
            }
            lines.push('');
        }

        return lines.join('\n');
    }

    private bucketByScanner(results: FixtureRunResult[]): Record<Scanner, ScannerBucket> {
        const buckets: Record<Scanner, ScannerBucket> = {
            'security-matrix': this.emptyBucket(),
            'checkov': this.emptyBucket(),
            'bandit': this.emptyBucket(),
            'semgrep': this.emptyBucket(),
        };
        for (const result of results) {
            const bucket = buckets[result.rule.scanner];
            bucket.total++;
            if (result.ungeneratable) bucket.ungeneratable++;
            else if (result.error) bucket.error++;
            else if (result.verdict?.overallPass) bucket.pass++;
            else bucket.fail++;
        }
        return buckets;
    }

    private emptyBucket(): ScannerBucket {
        return { total: 0, pass: 0, fail: 0, ungeneratable: 0, error: 0 };
    }

    private rescanSummary(rescan: FixtureRunResult['verdict'] extends undefined ? never : NonNullable<FixtureRunResult['verdict']>['rescan']): string {
        const parts: string[] = [];
        if (rescan.targetRuleStillFires) parts.push('still-fires');
        if (rescan.newRulesTriggered.length > 0) parts.push(`+${rescan.newRulesTriggered.length}-new`);
        if (!rescan.validationPassed) parts.push('parse-broken');
        return parts.length === 0 ? 'clean' : parts.join(' ');
    }

    private failurePriorityScore(result: FixtureRunResult): number {
        const v = result.verdict;
        if (!v) return 0;
        let score = 0;
        if (v.rescan.targetRuleStillFires) score += 10;
        if (v.effectiveness === 'LOW') score += 6;
        if (v.effectiveness === 'MEDIUM') score += 3;
        if (!v.rescan.validationPassed) score += 5;
        if (v.rescan.newRulesTriggered.length > 0) score += 2;
        if (v.efficiency !== 'HIGH') score += 1;
        return score;
    }
}
