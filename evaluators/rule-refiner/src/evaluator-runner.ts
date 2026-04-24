import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import type { RuleImplVerdict, ReviewVerdict } from './types.js';

interface ImplReport {
    verdicts: RuleImplVerdict[];
    jsonPath: string;
}

interface FixReport {
    verdicts: ReviewVerdict[];
    jsonPath: string;
}

export class EvaluatorRunner {
    private readonly implEvaluatorDir: string;
    private readonly fixEvaluatorDir: string;
    private readonly implReportsDir: string;
    private readonly fixReportsDir: string;

    constructor(evaluatorsRoot: string) {
        this.implEvaluatorDir = path.join(evaluatorsRoot, 'rule-impl-evaluator');
        this.fixEvaluatorDir = path.join(evaluatorsRoot, 'fix-agent-evaluator');
        this.implReportsDir = path.join(this.implEvaluatorDir, 'reports');
        this.fixReportsDir = path.join(this.fixEvaluatorDir, 'reports');
    }

    public async runImplEvaluator(ruleId: string): Promise<ImplReport> {
        const before = this.latestReport(this.implReportsDir, 'impl-review-');
        await this.spawnAsync(this.implEvaluatorDir, ['src/index.ts', '--rule', ruleId, '--concurrency', '1']);
        const after = this.latestReport(this.implReportsDir, 'impl-review-');
        if (!after || after === before) {
            throw new Error(`rule-impl-evaluator produced no new report for ${ruleId}`);
        }
        const verdicts = JSON.parse(fs.readFileSync(after, 'utf8')) as RuleImplVerdict[];
        return { verdicts, jsonPath: after };
    }

    public async runFixEvaluator(ruleId: string): Promise<FixReport> {
        const before = this.latestReport(this.fixReportsDir, 'evaluation-');
        await this.spawnAsync(this.fixEvaluatorDir, ['src/index.ts', '--rule', ruleId, '--concurrency', '1']);
        const after = this.latestReport(this.fixReportsDir, 'evaluation-');
        if (!after || after === before) {
            throw new Error(`fix-agent-evaluator produced no new report for ${ruleId}`);
        }
        const raw = JSON.parse(fs.readFileSync(after, 'utf8')) as { verdicts: ReviewVerdict[] };
        return { verdicts: raw.verdicts, jsonPath: after };
    }

    private latestReport(dir: string, prefix: string): string | null {
        if (!fs.existsSync(dir)) return null;
        const files = fs.readdirSync(dir)
            .filter(f => f.startsWith(prefix) && f.endsWith('.json'))
            .sort();
        if (files.length === 0) return null;
        return path.join(dir, files[files.length - 1]);
    }

    private spawnAsync(cwd: string, args: string[]): Promise<void> {
        return new Promise((resolve, reject) => {
            const child = spawn('bun', args, { cwd, stdio: 'inherit' });
            child.on('error', reject);
            child.on('close', code => {
                if (code !== 0) reject(new Error(`Evaluator exited with code ${code}`));
                else resolve();
            });
        });
    }
}
