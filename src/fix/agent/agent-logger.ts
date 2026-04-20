import { ContentBlock, Message } from '@aws-sdk/client-bedrock-runtime';
import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { ScanResult } from '../../assess/scanning/types.js';
import { ToolOutput } from './types.js';

const MAX_PREVIEW_CHARS = 2000;
const TAG = 'FixAgent';

/**
 * Structured debug logging for the fix agent. Writes to the standard SRT log
 * file (level: debug) so you can tail `~/.srt/logs/srt-tool.log` to observe
 * the full message exchange and tool usage without touching stdout.
 *
 * One FixAgent run is identified by a monotonically increasing sessionId so
 * that concurrent runs (should they exist) remain distinguishable.
 */
export class AgentLogger {
    private static nextSessionId = 1;
    private readonly sessionId: number;
    private turn = 0;

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

    public turnStarted(messagesSoFar: number): void {
        this.turn += 1;
        SrtLogger.logDebug(`${TAG}: turn started`, {
            sessionId: this.sessionId,
            turn: this.turn,
            messagesInContext: messagesSoFar,
        });
    }

    public assistantMessageReceived(message: Message, stopReason: string | undefined, usage?: Record<string, number | undefined>): void {
        SrtLogger.logDebug(`${TAG}: assistant message`, {
            sessionId: this.sessionId,
            turn: this.turn,
            stopReason: stopReason ?? 'unknown',
            text: this.extractText(message),
            toolUses: this.summariseToolUses(message),
            inputTokens: usage?.inputTokens,
            outputTokens: usage?.outputTokens,
        });
    }

    public toolInvoked(name: string, input: Record<string, unknown>): void {
        SrtLogger.logDebug(`${TAG}: tool invoke`, {
            sessionId: this.sessionId,
            turn: this.turn,
            tool: name,
            input: this.trimInput(input),
        });
    }

    public toolCompleted(name: string, output: ToolOutput, durationMs: number): void {
        SrtLogger.logDebug(`${TAG}: tool result`, {
            sessionId: this.sessionId,
            turn: this.turn,
            tool: name,
            isError: output.isError === true,
            durationMs,
            resultPreview: this.previewResult(output),
        });
    }

    public sessionEnded(stopReason: string, turns: number, editCount: number, comments: string): void {
        SrtLogger.logDebug(`${TAG}: session ended`, {
            sessionId: this.sessionId,
            stopReason,
            turns,
            edits: editCount,
            comments: this.preview(comments),
        });
    }

    private extractText(message: Message): string {
        const parts = (message.content ?? [])
            .map(block => block.text)
            .filter((text): text is string => typeof text === 'string' && text.length > 0);
        return this.preview(parts.join('\n'));
    }

    private summariseToolUses(message: Message): Array<{ name: string; id?: string; input: unknown }> {
        return (message.content ?? [])
            .map((block: ContentBlock) => block.toolUse)
            .filter((tu): tu is NonNullable<typeof tu> => Boolean(tu))
            .map(tu => ({
                name: tu.name ?? 'unknown',
                id: tu.toolUseId,
                input: this.trimInput((tu.input ?? {}) as Record<string, unknown>),
            }));
    }

    private trimInput(input: Record<string, unknown>): Record<string, unknown> {
        const trimmed: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(input)) {
            trimmed[key] = typeof value === 'string' ? this.preview(value) : value;
        }
        return trimmed;
    }

    private previewResult(output: ToolOutput): string {
        if (output.text !== undefined) return this.preview(output.text);
        try {
            return this.preview(JSON.stringify(output.json));
        } catch {
            return '[unserialisable]';
        }
    }

    private preview(value: string): string {
        if (value.length <= MAX_PREVIEW_CHARS) return value;
        return `${value.slice(0, MAX_PREVIEW_CHARS)}…[truncated ${value.length - MAX_PREVIEW_CHARS} chars]`;
    }
}
