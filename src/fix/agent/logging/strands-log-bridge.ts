import { configureLogging, Logger } from '@strands-agents/sdk';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';

const TAG = 'strands-sdk';

/**
 * Bridges the Strands SDK's global logger to SrtLogger so the SDK's own
 * internal diagnostics (model calls, tool dispatching, streaming) land in
 * `~/.srt/logs/srt-tool.log` alongside the agent's session-level events.
 *
 * Idempotent — safe to call more than once.
 */
export function bridgeStrandsLoggingToSrt(): void {
    if (bridged) return;
    bridged = true;
    configureLogging(createBridgedLogger());
}

let bridged = false;

function createBridgedLogger(): Logger {
    return {
        debug: (...args) => SrtLogger.logDebug(`${TAG}: ${formatArgs(args)}`),
        info: (...args) => SrtLogger.logInfo(`${TAG}: ${formatArgs(args)}`),
        warn: (...args) => SrtLogger.logDebug(`${TAG} [warn]: ${formatArgs(args)}`),
        error: (...args) => SrtLogger.logError(`${TAG}: ${formatArgs(args)}`, extractError(args)),
    };
}

function formatArgs(args: unknown[]): string {
    return args.map(formatOne).join(' ');
}

function formatOne(value: unknown): string {
    if (value instanceof Error) return value.message;
    if (typeof value === 'string') return value;
    try {
        return JSON.stringify(value);
    } catch {
        return String(value);
    }
}

function extractError(args: unknown[]): unknown {
    return args.find(arg => arg instanceof Error) ?? new Error(formatArgs(args));
}
