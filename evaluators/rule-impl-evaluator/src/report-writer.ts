import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Correctness, RuleImplVerdict } from './types.js';

export class ReportWriter {
    constructor(private readonly reportsDir: string) {}

    public async write(verdicts: RuleImplVerdict[]): Promise<{ markdownPath: string; jsonPath: string }> {
        fs.mkdirSync(this.reportsDir, { recursive: true });
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const markdownPath = path.join(this.reportsDir, `impl-review-${timestamp}.md`);
        const jsonPath = path.join(this.reportsDir, `impl-review-${timestamp}.json`);

        fs.writeFileSync(markdownPath, this.renderMarkdown(verdicts), 'utf8');
        fs.writeFileSync(jsonPath, JSON.stringify(verdicts, null, 2), 'utf8');
        return { markdownPath, jsonPath };
    }

    private renderMarkdown(verdicts: RuleImplVerdict[]): string {
        const counts = this.tally(verdicts);
        const incorrect = verdicts.filter(v => v.correctness === 'INCORRECT');
        const partial = verdicts.filter(v => v.correctness === 'PARTIAL');
        const correct = verdicts.filter(v => v.correctness === 'CORRECT');

        const lines: string[] = [];
        lines.push(`# Rule Implementation Review`);
        lines.push('');
        lines.push(`Total rules reviewed: ${verdicts.length}`);
        lines.push(`  - CORRECT:   ${counts.CORRECT}`);
        lines.push(`  - PARTIAL:   ${counts.PARTIAL}`);
        lines.push(`  - INCORRECT: ${counts.INCORRECT}`);
        lines.push('');

        if (incorrect.length > 0) {
            lines.push(`## INCORRECT (${incorrect.length})`);
            lines.push('');
            for (const v of incorrect) lines.push(...this.renderVerdict(v));
        }

        if (partial.length > 0) {
            lines.push(`## PARTIAL (${partial.length})`);
            lines.push('');
            for (const v of partial) lines.push(...this.renderVerdict(v));
        }

        if (correct.length > 0) {
            lines.push(`## CORRECT (${correct.length})`);
            lines.push('');
            lines.push(`<details><summary>Expand</summary>`);
            lines.push('');
            for (const v of correct) lines.push(...this.renderVerdict(v, true));
            lines.push(`</details>`);
        }

        return lines.join('\n');
    }

    private renderVerdict(verdict: RuleImplVerdict, compact = false): string[] {
        const lines: string[] = [];
        lines.push(`### ${verdict.checkId}`);
        lines.push('');
        if (verdict.ruleDescription) {
            lines.push(`**Rule:** ${verdict.ruleDescription}`);
            lines.push('');
        }
        lines.push(`**Reasoning:** ${verdict.correctnessReasoning}`);
        if (!compact || verdict.missedCases.length > 0) {
            if (verdict.missedCases.length > 0) {
                lines.push('');
                lines.push(`**Missed cases:**`);
                for (const c of verdict.missedCases) lines.push(`  - ${c}`);
            }
        }
        if (verdict.falsePositiveRisks.length > 0) {
            lines.push('');
            lines.push(`**False-positive risks:**`);
            for (const c of verdict.falsePositiveRisks) lines.push(`  - ${c}`);
        }
        if (verdict.suggestedLogicChanges) {
            lines.push('');
            lines.push(`**Suggested logic changes:**`);
            lines.push(verdict.suggestedLogicChanges);
        }
        if (verdict.awsDocCitations.length > 0) {
            lines.push('');
            lines.push(`**AWS doc citations:**`);
            for (const url of verdict.awsDocCitations) lines.push(`  - ${url}`);
        }
        lines.push('');
        return lines;
    }

    private tally(verdicts: RuleImplVerdict[]): Record<Correctness, number> {
        const counts: Record<Correctness, number> = { CORRECT: 0, PARTIAL: 0, INCORRECT: 0 };
        for (const v of verdicts) counts[v.correctness]++;
        return counts;
    }
}
