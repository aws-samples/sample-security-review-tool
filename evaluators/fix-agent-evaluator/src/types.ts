import type { ScanResult } from '../../../src/assess/scanning/types.js';
import type { Fix } from '../../../src/fix/types.js';
import type { RescanResult } from './rescan-checker.js';

export type { RescanResult } from './rescan-checker.js';

/**
 * The outcome of running the fix agent against a single finding.
 * Captures everything the reviewer needs to render a verdict:
 *   - the finding itself (so we know what was supposed to be fixed),
 *   - the Fix object the agent produced (if any),
 *   - the agent session transcript harvested from the SRT debug log,
 *   - the git diff of files the agent modified.
 */
export interface FixRunRecord {
    issue: ScanResult;
    fix: Fix | null;
    applied: boolean;
    session: AgentSession;
    diff: string;
    durationMs: number;
}

/**
 * A single fix agent run as reconstructed from the SRT debug log.
 * AgentLogger emits one session per finding with a monotonically increasing
 * sessionId, so we can slice the log cleanly.
 */
export interface AgentSession {
    sessionId: number | null;
    turns: number;
    stopReason: string;
    /** Number of `apply_fix` calls the agent made. */
    applyFixAttempts: number;
    /** Number of `apply_fix` calls that returned a semantic failure (`valid: false` or `applied: false`). */
    applyFixFailures: number;
    /**
     * Retries = failed attempts to produce a valid fix. Equal to
     * applyFixFailures — each failure is a retry the agent had to make.
     */
    retries: number;
    toolInvocations: ToolInvocationSummary[];
    /** Validation errors from each failed apply_fix attempt (one inner array per attempt). */
    applyFixFailureDetails: ApplyFixFailureDetail[][];
    finalComments: string;
    rawLogLines: string[];
}

export interface ToolInvocationSummary {
    turn: number;
    tool: string;
    /** Tool threw an exception (e.g. invalid input that escaped Zod). */
    isError: boolean;
    /**
     * Tool returned cleanly but signalled a semantic failure — for apply_fix,
     * that is `valid: false` or `applied: false`. Used as the retry signal.
     */
    isFailure: boolean;
    durationMs: number | null;
    /** Validation errors from a failed apply_fix call, parsed from the log's resultPreview. */
    failureDetails?: ApplyFixFailureDetail[];
}

export interface ApplyFixFailureDetail {
    strategy: string;
    output: string;
}

export type Rating = 'HIGH' | 'MEDIUM' | 'LOW';

export interface ReviewVerdict {
    checkId: string;
    source: string;
    path: string;
    resourceName?: string;
    effectiveness: Rating;
    effectivenessReasoning: string;
    efficiency: Rating;
    efficiencyReasoning: string;
    turns: number;
    retries: number;
    applyFixFailures: number;
    rootCause: string;
    currentFixGuidance: string;
    suggestedFixGuidance: string;
    additionalRecommendations: string;
    rescan: RescanResult;
    overallPass: boolean;
    failureReasons: string[];
}
