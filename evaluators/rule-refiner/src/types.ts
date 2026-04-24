import type { RuleImplVerdict } from '../../rule-impl-evaluator/src/types.js';
import type { ReviewVerdict } from '../../fix-agent-evaluator/src/types.js';

export type { RuleImplVerdict, ReviewVerdict };

export type Phase = 'impl' | 'fix';

export interface RefineOptions {
    ruleId: string;
    phases: Phase[];
    maxIterations: number;
}

export interface PhaseResult {
    phase: Phase;
    passed: boolean;
    iterations: number;
    durationMs: number;
}

export interface EvaluatorReport<T> {
    jsonPath: string;
    verdicts: T[];
}
