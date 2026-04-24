import type { Phase, PhaseResult } from './types.js';
import type { EvaluatorRunner } from './evaluator-runner.js';
import type { ClaudeRunner } from './claude-runner.js';
import { buildImplPrompt, buildFixPrompt } from './prompts.js';

const CYAN = '\x1b[0;36m';
const GREEN = '\x1b[0;32m';
const YELLOW = '\x1b[0;33m';
const RED = '\x1b[0;31m';
const MAGENTA = '\x1b[0;35m';
const BOLD = '\x1b[1m';
const NC = '\x1b[0m';

function log(color: string, msg: string): void {
    console.log(`${color}${msg}${NC}`);
}

export class PhaseRunner {
    constructor(
        private readonly evaluator: EvaluatorRunner,
        private readonly claude: ClaudeRunner,
    ) {}

    public async runImpl(ruleId: string, maxIterations: number): Promise<PhaseResult> {
        return this.runPhase('impl', ruleId, maxIterations);
    }

    public async runFix(ruleId: string, maxIterations: number): Promise<PhaseResult> {
        return this.runPhase('fix', ruleId, maxIterations);
    }

    private async runPhase(phase: Phase, ruleId: string, maxIterations: number): Promise<PhaseResult> {
        const label = phase === 'impl' ? 'Detection Logic' : 'Fix Guidance';
        log(MAGENTA + BOLD, `\n=== Phase: ${label} (${ruleId}) ===`);

        const start = Date.now();

        for (let iteration = 1; iteration <= maxIterations; iteration++) {
            log(CYAN, `\n--- Iteration ${iteration}/${maxIterations} ---`);

            log(CYAN, 'Running evaluator...');
            const prompt = phase === 'impl'
                ? await this.evaluateImpl(ruleId)
                : await this.evaluateFix(ruleId);

            if (prompt === null) {
                log(GREEN, `${label}: PASSED`);
                return { phase, passed: true, iterations: iteration, durationMs: Date.now() - start };
            }

            if (iteration === maxIterations) break;

            log(YELLOW, 'Sending report to Claude for fixes...');
            await this.claude.run(prompt);
            log(CYAN, 'Fixes applied. Re-evaluating...');
        }

        log(RED, `${label}: max iterations reached without passing.`);
        return { phase, passed: false, iterations: maxIterations, durationMs: Date.now() - start };
    }

    private async evaluateImpl(ruleId: string): Promise<string | null> {
        const report = await this.evaluator.runImplEvaluator(ruleId);
        const verdict = report.verdicts.find(v => v.checkId === ruleId);
        if (!verdict) {
            throw new Error(`No verdict found for ${ruleId} in impl evaluator report`);
        }
        if (verdict.correctness === 'CORRECT') return null;
        return buildImplPrompt(ruleId, verdict);
    }

    private async evaluateFix(ruleId: string): Promise<string | null> {
        const report = await this.evaluator.runFixEvaluator(ruleId);
        const ruleVerdicts = report.verdicts.filter(v => v.checkId === ruleId);
        if (ruleVerdicts.length === 0) {
            throw new Error(`No verdicts found for ${ruleId} in fix evaluator report`);
        }
        const failures = ruleVerdicts.filter(v => !v.overallPass);
        if (failures.length === 0) return null;
        return buildFixPrompt(ruleId, failures);
    }
}
