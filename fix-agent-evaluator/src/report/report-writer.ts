import * as fs from 'node:fs';
import * as path from 'node:path';
import type { FixRunRecord, ReviewVerdict } from '../types.js';

/**
 * Writes the evaluation report in markdown and JSON. The markdown is intended
 * for human consumption (PR description, ticket); the JSON is for downstream
 * tooling.
 */
export class ReportWriter {
    constructor(private readonly outputDir: string) {}

    public write(records: FixRunRecord[], verdicts: ReviewVerdict[]): { markdownPath: string; jsonPath: string } {
        fs.mkdirSync(this.outputDir, { recursive: true });
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const markdownPath = path.join(this.outputDir, `evaluation-${timestamp}.md`);
        const jsonPath = path.join(this.outputDir, `evaluation-${timestamp}.json`);

        fs.writeFileSync(markdownPath, this.renderMarkdown(records, verdicts), 'utf8');
        fs.writeFileSync(jsonPath, JSON.stringify({ verdicts, summary: this.summarize(verdicts) }, null, 2), 'utf8');

        return { markdownPath, jsonPath };
    }

    private renderMarkdown(records: FixRunRecord[], verdicts: ReviewVerdict[]): string {
        const summary = this.summarize(verdicts);
        const sections: string[] = [];

        sections.push(`# Fix Agent Evaluation\n`);
        sections.push(`Generated: ${new Date().toISOString()}\n`);
        sections.push(`## Summary\n`);
        sections.push(`- Total findings reviewed: ${verdicts.length}`);
        sections.push(`- Ineffective fixes (effectiveness = LOW or MEDIUM): ${summary.ineffective}`);
        sections.push(`- Inefficient fixes (efficiency = LOW or MEDIUM): ${summary.inefficient}`);
        sections.push(`- Fixes needing rule guidance updates: ${summary.needGuidanceUpdate}\n`);

        const problematic = this.sortProblematicFirst(verdicts);
        sections.push(`## Findings\n`);
        for (const verdict of problematic) {
            sections.push(this.renderVerdict(verdict, records.find(r => r.issue.check_id === verdict.checkId && r.issue.path === verdict.path)));
        }
        return sections.join('\n');
    }

    private renderVerdict(verdict: ReviewVerdict, record: FixRunRecord | undefined): string {
        const icon = verdict.effectiveness === 'HIGH' && verdict.efficiency === 'HIGH' ? '✅' : '❌';
        const lines: string[] = [];
        lines.push(`### ${icon} ${verdict.checkId} — ${verdict.path}${verdict.resourceName ? ` (${verdict.resourceName})` : ''}`);
        lines.push('');
        lines.push(`- Effectiveness: **${verdict.effectiveness}** — ${verdict.effectivenessReasoning}`);
        lines.push(`- Efficiency: **${verdict.efficiency}** — ${verdict.efficiencyReasoning} (retries: ${verdict.retries}, turns: ${verdict.turns}, apply_fix failures: ${verdict.applyFixFailures})`);
        lines.push(`- Root cause: ${verdict.rootCause}`);
        lines.push('');
        lines.push(`**Current fix guidance:**`);
        lines.push('```');
        lines.push(verdict.currentFixGuidance || '(none)');
        lines.push('```');
        if (verdict.suggestedFixGuidance) {
            lines.push(`**Recommended replacement (drop-in for the rule's \`fix\` string):**`);
            lines.push('```');
            lines.push(verdict.suggestedFixGuidance);
            lines.push('```');
        }
        if (verdict.additionalRecommendations) {
            lines.push(`**Additional recommendations:** ${verdict.additionalRecommendations}`);
        }
        if (record?.session.finalComments) {
            lines.push('');
            lines.push(`**Fix agent final comments:** ${record.session.finalComments}`);
        }
        lines.push('');
        return lines.join('\n');
    }

    private sortProblematicFirst(verdicts: ReviewVerdict[]): ReviewVerdict[] {
        const rank = (v: ReviewVerdict) =>
            (v.effectiveness === 'LOW' ? 0 : v.effectiveness === 'MEDIUM' ? 1 : 2) * 10 +
            (v.efficiency === 'LOW' ? 0 : v.efficiency === 'MEDIUM' ? 1 : 2);
        return [...verdicts].sort((a, b) => rank(a) - rank(b));
    }

    private summarize(verdicts: ReviewVerdict[]): { ineffective: number; inefficient: number; needGuidanceUpdate: number } {
        return {
            ineffective: verdicts.filter(v => v.effectiveness !== 'HIGH').length,
            inefficient: verdicts.filter(v => v.efficiency !== 'HIGH').length,
            needGuidanceUpdate: verdicts.filter(v => v.suggestedFixGuidance.length > 0).length,
        };
    }
}
