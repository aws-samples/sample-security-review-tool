import * as fs from 'node:fs';
import * as path from 'node:path';
import type { RefinerResult } from '../types.js';

export class ReportWriter {
    constructor(private readonly outputDir: string) {}

    public write(results: RefinerResult[]): { markdownPath: string; jsonPath: string } {
        fs.mkdirSync(this.outputDir, { recursive: true });
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const markdownPath = path.join(this.outputDir, `refine-${timestamp}.md`);
        const jsonPath = path.join(this.outputDir, `refine-${timestamp}.json`);

        fs.writeFileSync(markdownPath, this.renderMarkdown(results), 'utf8');
        fs.writeFileSync(jsonPath, JSON.stringify(results, null, 2), 'utf8');

        return { markdownPath, jsonPath };
    }

    private renderMarkdown(results: RefinerResult[]): string {
        const lines: string[] = [];
        lines.push('# Rule Refiner Report');
        lines.push('');
        lines.push(`Generated: ${new Date().toISOString()}`);
        lines.push(`Total rules refined: ${results.length}`);
        lines.push('');

        const p1Correct = results.filter(r => r.phase1.correctness === 'CORRECT').length;
        const p1Edited = results.filter(r => r.phase1.detectionLogicEdited).length;
        lines.push(`Phase 1: ${p1Correct}/${results.length} CORRECT (${p1Edited} edited)`);

        const allVariants = results.flatMap(r => r.phase2.variantResults);
        const p2Pass = allVariants.filter(v => v.effectiveness === 'HIGH').length;
        const p2Edited = allVariants.filter(v => v.fixGuidanceEdited).length;
        lines.push(`Phase 2: ${p2Pass}/${allVariants.length} variants HIGH effectiveness (${p2Edited} guidance edits)`);
        lines.push('');

        for (const result of results) {
            lines.push(`## ${result.checkId}`);
            lines.push('');
            lines.push('### Phase 1: Detection Logic');
            lines.push(`- Correctness: **${result.phase1.correctness}**`);
            lines.push(`- Edited: ${result.phase1.detectionLogicEdited ? 'Yes' : 'No'}`);
            if (result.phase1.editSummary) lines.push(`- Edit: ${result.phase1.editSummary}`);
            lines.push(`- Reasoning: ${result.phase1.correctnessReasoning}`);
            if (result.phase1.awsDocCitations.length > 0) {
                lines.push(`- Citations: ${result.phase1.awsDocCitations.join(', ')}`);
            }
            if (result.phase1.missedCases.length > 0) {
                lines.push('- Missed cases:');
                for (const c of result.phase1.missedCases) lines.push(`  - ${c}`);
            }
            if (result.phase1.falsePositiveRisks.length > 0) {
                lines.push('- False-positive risks:');
                for (const r of result.phase1.falsePositiveRisks) lines.push(`  - ${r}`);
            }
            if (result.phase1.knownLimitations.length > 0) {
                lines.push('- Known limitations:');
                for (const l of result.phase1.knownLimitations) lines.push(`  - ${l}`);
            }
            lines.push('');

            if (result.phase2.variantResults.length > 0) {
                lines.push('### Phase 2: Fix Guidance');
                for (const v of result.phase2.variantResults) {
                    const icon = v.effectiveness === 'HIGH' && v.efficiency === 'HIGH' ? 'PASS' : 'FAIL';
                    lines.push(`#### [${icon}] ${v.variantId} (${v.format})`);
                    lines.push(`- Effectiveness: **${v.effectiveness}** — ${v.effectivenessReasoning}`);
                    lines.push(`- Efficiency: **${v.efficiency}** — ${v.efficiencyReasoning}`);
                    lines.push(`- Rescan passed: ${v.rescanPassed}`);
                    lines.push(`- Guidance edited: ${v.fixGuidanceEdited ? 'Yes' : 'No'}`);
                    if (v.editSummary) lines.push(`- Edit: ${v.editSummary}`);
                    lines.push('');
                }
            }
        }

        return lines.join('\n');
    }
}
