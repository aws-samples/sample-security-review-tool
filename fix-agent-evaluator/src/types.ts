import type { ScanResult } from '../../src/assess/scanning/types.js';
import type { Fix } from '../../src/fix/types.js';

/**
 * The outcome of running the FixAgent against a single finding.
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
 * A single FixAgent run as reconstructed from the SRT debug log.
 * AgentLogger emits one session per finding with a monotonically increasing
 * sessionId, so we can slice the log cleanly.
 */
export interface AgentSession {
    sessionId: number | null;
    turns: number;
    stopReason: string;
    validateFixInvocations: number;
    validateFixFailures: number;
    /**
     * Count of tool invocations that represent a retry: any failed
     * validate_fix, edit_file, or apply_edits call. These indicate the agent
     * attempted to produce or commit a fix and had to try again.
     */
    retries: number;
    toolInvocations: ToolInvocationSummary[];
    finalComments: string;
    rawLogLines: string[];
}

export interface ToolInvocationSummary {
    turn: number;
    tool: string;
    isError: boolean;
    durationMs: number | null;
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
    validateFixFailures: number;
    rootCause: string;
    currentFixGuidance: string;
    suggestedFixGuidance: string;
    additionalRecommendations: string;
}
