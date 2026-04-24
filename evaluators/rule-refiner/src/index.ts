import * as path from 'node:path';
import * as url from 'node:url';
import type { Phase, PhaseResult } from './types.js';
import { EvaluatorRunner } from './evaluator-runner.js';
import { ClaudeRunner } from './claude-runner.js';
import { PhaseRunner } from './phase-runner.js';

const GREEN = '\x1b[0;32m';
const YELLOW = '\x1b[0;33m';
const RED = '\x1b[0;31m';
const MAGENTA = '\x1b[0;35m';
const BOLD = '\x1b[1m';
const CYAN = '\x1b[0;36m';
const NC = '\x1b[0m';

interface ParsedArgs {
    ruleId: string;
    phases: Phase[];
    maxIterations: number;
}

function parseArgs(argv: string[]): ParsedArgs {
    const result: ParsedArgs = {
        ruleId: '',
        phases: ['impl', 'fix'],
        maxIterations: 5,
    };

    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        const consumeValue = (): string => {
            const next = argv[i + 1];
            if (next === undefined) throw new Error(`Missing value for ${arg}`);
            i++;
            return next;
        };
        switch (arg) {
            case '--rule':
                result.ruleId = consumeValue();
                break;
            case '--phase': {
                const value = consumeValue();
                if (value !== 'impl' && value !== 'fix' && value !== 'both') {
                    throw new Error(`--phase must be 'impl', 'fix', or 'both'`);
                }
                result.phases = value === 'both' ? ['impl', 'fix'] : [value];
                break;
            }
            case '--max-iterations': {
                const value = Number(consumeValue());
                if (!Number.isFinite(value) || value < 1) {
                    throw new Error('--max-iterations must be a positive integer');
                }
                result.maxIterations = Math.floor(value);
                break;
            }
            case '-h':
            case '--help':
                printUsage();
                process.exit(0);
                break;
            default:
                throw new Error(`Unknown argument: ${arg}`);
        }
    }

    if (!result.ruleId) {
        throw new Error('--rule <RULE_ID> is required');
    }

    return result;
}

function printUsage(): void {
    console.log(`Usage:
  bun src/index.ts --rule <checkId>                  # both phases, default 5 iterations each
  bun src/index.ts --rule <checkId> --max-iterations 3
  bun src/index.ts --rule <checkId> --phase impl     # detection logic only
  bun src/index.ts --rule <checkId> --phase fix      # fix guidance only
`);
}

function formatDuration(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    if (minutes === 0) return `${seconds}s`;
    return `${minutes}m ${remainingSeconds}s`;
}

function printSummary(results: PhaseResult[]): void {
    console.log(`\n${MAGENTA}${BOLD}=== Summary ===${NC}`);
    const totalMs = results.reduce((sum, r) => sum + r.durationMs, 0);
    for (const r of results) {
        const label = r.phase === 'impl' ? 'Detection Logic' : 'Fix Guidance';
        const status = r.passed ? `${GREEN}PASSED${NC}` : `${RED}FAILED${NC}`;
        console.log(`  ${label}: ${status} (${r.iterations} iteration(s), ${formatDuration(r.durationMs)})`);
    }
    console.log(`${CYAN}  Total time: ${formatDuration(totalMs)}${NC}`);
    if (results.every(r => r.passed)) {
        console.log(`\n${GREEN}${BOLD}All phases passed.${NC}`);
    } else {
        console.log(`\n${YELLOW}Changes are uncommitted. Review and commit when ready.${NC}`);
    }
}

async function main(): Promise<void> {
    const args = parseArgs(process.argv.slice(2));

    const moduleDir = path.dirname(url.fileURLToPath(import.meta.url));
    const evaluatorsRoot = path.resolve(moduleDir, '..', '..');
    const srtRepoRoot = path.resolve(evaluatorsRoot, '..');

    const evaluator = new EvaluatorRunner(evaluatorsRoot);
    const claude = new ClaudeRunner(srtRepoRoot);
    const runner = new PhaseRunner(evaluator, claude);

    console.log(`${MAGENTA}${BOLD}=== Rule Refiner: ${args.ruleId} ===${NC}`);
    console.log(`${CYAN}Phases: ${args.phases.join(', ')} | Max iterations: ${args.maxIterations}${NC}`);

    const results: PhaseResult[] = [];

    for (const phase of args.phases) {
        const result = phase === 'impl'
            ? await runner.runImpl(args.ruleId, args.maxIterations)
            : await runner.runFix(args.ruleId, args.maxIterations);
        results.push(result);

        if (!result.passed) break;
    }

    printSummary(results);

    const allPassed = results.every(r => r.passed);
    process.exit(allPassed ? 0 : 2);
}

main().catch(error => {
    console.error(`${RED}${error.message}${NC}`);
    process.exit(1);
});
