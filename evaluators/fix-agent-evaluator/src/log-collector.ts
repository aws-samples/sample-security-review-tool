import type { ScanResult } from '../../../src/assess/scanning/types.js';
import type { AgentSession, ToolInvocationSummary } from './types.js';

const SESSION_STARTED = 'StrandsFixAgent: session started';
const SESSION_ENDED = 'StrandsFixAgent: session ended';
const TOOL_RESULT = 'StrandsFixAgent: tool result';

/**
 * Parses fix-agent session transcripts out of the SRT debug log.
 *
 * AgentLogger writes lines like:
 *   2026-04-22 13:14:00 [DEBUG]: StrandsFixAgent: session started {sessionId=3, checkId=S3-008, ...}
 *   ...
 *   2026-04-22 13:14:45 [DEBUG]: StrandsFixAgent: session ended {sessionId=3, turns=4, ...}
 *
 * The parser extracts the block for the session that matches a given finding
 * and derives a tool invocation summary, apply_fix failure count, and the
 * final `comments` value.
 */
export class AgentSessionParser {
    public parseSession(logLines: string[], issue: ScanResult): AgentSession {
        const block = this.findSessionBlock(logLines, issue);
        if (block.length === 0) {
            return this.emptySession();
        }

        const startedFields = this.parseFields(block[0]);
        const endedLine = block.findLast(line => line.includes(SESSION_ENDED));
        const endedFields = endedLine ? this.parseFields(endedLine) : {};

        const toolInvocations = this.extractToolInvocations(block);
        const applyFixCalls = toolInvocations.filter(t => t.tool === 'apply_fix');
        const applyFixAttempts = applyFixCalls.length;
        const applyFixFailures = applyFixCalls.filter(t => t.isFailure || t.isError).length;
        const retries = applyFixFailures;

        return {
            sessionId: this.toNumber(startedFields.sessionId),
            turns: this.toNumber(endedFields.turns) ?? toolInvocations.length,
            stopReason: this.stripQuotes(endedFields.stopReason ?? 'unknown'),
            applyFixAttempts,
            applyFixFailures,
            retries,
            toolInvocations,
            finalComments: this.stripQuotes(endedFields.comments ?? ''),
            rawLogLines: block,
        };
    }

    private findSessionBlock(logLines: string[], issue: ScanResult): string[] {
        // Match the "session started" line that references this finding's checkId + path.
        // Then take lines up through the next "session ended" with the same sessionId.
        const startIndex = logLines.findIndex(line => this.isSessionStartFor(line, issue));
        if (startIndex === -1) return [];

        const startedFields = this.parseFields(logLines[startIndex]);
        const sessionId = startedFields.sessionId;

        for (let i = startIndex + 1; i < logLines.length; i++) {
            const line = logLines[i];
            if (line.includes(SESSION_ENDED)) {
                const fields = this.parseFields(line);
                if (fields.sessionId === sessionId) {
                    return logLines.slice(startIndex, i + 1);
                }
            }
        }
        return logLines.slice(startIndex);
    }

    private isSessionStartFor(line: string, issue: ScanResult): boolean {
        if (!line.includes(SESSION_STARTED)) return false;
        const fields = this.parseFields(line);
        if (issue.check_id && fields.checkId !== issue.check_id) return false;
        if (issue.path && fields.path && fields.path !== issue.path) return false;
        return true;
    }

    private extractToolInvocations(block: string[]): ToolInvocationSummary[] {
        const invocations: ToolInvocationSummary[] = [];
        for (const line of block) {
            if (line.includes(TOOL_RESULT)) {
                const fields = this.parseFields(line);
                invocations.push({
                    turn: this.toNumber(fields.turn) ?? 0,
                    tool: this.stripQuotes(fields.tool ?? 'unknown'),
                    isError: fields.isError === 'true',
                    isFailure: fields.isFailure === 'true',
                    durationMs: this.toNumber(fields.durationMs),
                });
            }
        }
        return invocations;
    }

    /**
     * Parses the pseudo-key-value payload written by SrtLogger.formatContext.
     * Format: {k=v, k2=v2, k3={"nested":"json"}}
     * We tolerate JSON values by scanning for the matching brace.
     */
    private parseFields(line: string): Record<string, string> {
        const result: Record<string, string> = {};
        const openBrace = line.indexOf('{');
        if (openBrace === -1) return result;
        const payload = line.slice(openBrace + 1, line.lastIndexOf('}'));

        let cursor = 0;
        while (cursor < payload.length) {
            const equalsIndex = payload.indexOf('=', cursor);
            if (equalsIndex === -1) break;
            const key = payload.slice(cursor, equalsIndex).trim();
            const valueStart = equalsIndex + 1;
            const valueEnd = this.findValueEnd(payload, valueStart);
            const value = payload.slice(valueStart, valueEnd).trim();
            result[key] = value;
            cursor = valueEnd + 2; // skip ", "
        }
        return result;
    }

    private findValueEnd(payload: string, start: number): number {
        if (payload[start] === '{' || payload[start] === '[') {
            return this.matchingClose(payload, start) + 1;
        }
        if (payload[start] === '"') {
            const closing = payload.indexOf('"', start + 1);
            return closing === -1 ? payload.length : closing + 1;
        }
        const commaIndex = payload.indexOf(', ', start);
        return commaIndex === -1 ? payload.length : commaIndex;
    }

    private matchingClose(payload: string, start: number): number {
        const open = payload[start];
        const close = open === '{' ? '}' : ']';
        let depth = 0;
        for (let i = start; i < payload.length; i++) {
            if (payload[i] === open) depth++;
            else if (payload[i] === close) {
                depth--;
                if (depth === 0) return i;
            }
        }
        return payload.length - 1;
    }

    private toNumber(value: string | undefined): number | null {
        if (value === undefined) return null;
        const n = Number(value);
        return Number.isFinite(n) ? n : null;
    }

    private stripQuotes(value: string): string {
        if (value.startsWith('"') && value.endsWith('"')) return value.slice(1, -1);
        return value;
    }

    private emptySession(): AgentSession {
        return {
            sessionId: null,
            turns: 0,
            stopReason: 'no-session-found',
            applyFixAttempts: 0,
            applyFixFailures: 0,
            retries: 0,
            toolInvocations: [],
            finalComments: '',
            rawLogLines: [],
        };
    }
}
