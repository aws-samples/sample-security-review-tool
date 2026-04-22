import { Message } from '@strands-agents/sdk';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';
import { ScanResult } from '../../../assess/scanning/types.js';

const MAX_PREVIEW_CHARS = 2000;
const TAG = 'StrandsFixAgent';

/**
 * Structured debug logging for the fix agent. Writes to the standard SRT log
 * file (level: debug) so the full message exchange and tool usage can be
 * observed by tailing `~/.srt/logs/srt-tool.log`.
 *
 * One agent run is identified by a monotonically increasing sessionId so
 * concurrent runs remain distinguishable.
 */
export class AgentLogger {
    private static nextSessionId = 1;
    private readonly sessionId: number;
    private toolCallIndex = 0;

    constructor() {
        this.sessionId = AgentLogger.nextSessionId++;
    }

    public sessionStarted(issue: ScanResult, systemPromptLength: number, userPrompt: string): void {
        SrtLogger.logDebug(`${TAG}: session started`, {
            sessionId: this.sessionId,
            source: issue.source,
            checkId: issue.check_id,
            path: issue.path,
            line: issue.line,
            resourceName: issue.resourceName,
            cdkPath: issue.cdkPath,
            systemPromptLength,
            userPromptPreview: this.preview(userPrompt),
        });
    }

    public assistantMessage(message: Message): void {
        SrtLogger.logDebug(`${TAG}: assistant message`, {
            sessionId: this.sessionId,
            text: this.extractText(message),
        });
    }

    public toolInvoked(name: string, input: unknown): void {
        this.toolCallIndex += 1;
        SrtLogger.logDebug(`${TAG}: tool invoke`, {
            sessionId: this.sessionId,
            turn: this.toolCallIndex,
            tool: name,
            input: this.trimInput(input) as object,
        });
    }

    public toolCompleted(name: string, result: unknown, isError: boolean, durationMs: number): void {
        SrtLogger.logDebug(`${TAG}: tool result`, {
            sessionId: this.sessionId,
            turn: this.toolCallIndex,
            tool: name,
            isError,
            isFailure: this.detectSemanticFailure(result),
            durationMs,
            resultPreview: this.previewResult(result),
        });
    }

    public sessionEnded(stopReason: string, editCount: number, comments: string): void {
        SrtLogger.logDebug(`${TAG}: session ended`, {
            sessionId: this.sessionId,
            stopReason,
            turns: this.toolCallIndex,
            edits: editCount,
            comments: this.preview(comments),
        });
    }

    /**
     * A tool completed without throwing but returned a semantic failure — for
     * apply_fix, that means validation rejected the attempt or the input was
     * malformed. The evaluator uses this to count retries without parsing the
     * preview JSON.
     */
    private detectSemanticFailure(result: unknown): boolean {
        if (!result || typeof result !== 'object') return false;
        const payload = result as Record<string, unknown>;
        if (payload.valid === false) return true;
        if (payload.applied === false) return true;
        return false;
    }

    private extractText(message: Message): string {
        const parts = (message.content ?? [])
            .map(block => (block as { text?: string }).text)
            .filter((text): text is string => typeof text === 'string' && text.length > 0);
        return this.preview(parts.join('\n'));
    }

    private trimInput(input: unknown): unknown {
        if (!input || typeof input !== 'object') return input;
        const trimmed: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
            trimmed[key] = typeof value === 'string' ? this.preview(value) : value;
        }
        return trimmed;
    }

    private previewResult(result: unknown): string {
        if (typeof result === 'string') return this.preview(result);
        try {
            return this.preview(JSON.stringify(result));
        } catch {
            return '[unserialisable]';
        }
    }

    private preview(value: string): string {
        if (value.length <= MAX_PREVIEW_CHARS) return value;
        return `${value.slice(0, MAX_PREVIEW_CHARS)}…[truncated ${value.length - MAX_PREVIEW_CHARS} chars]`;
    }
}
