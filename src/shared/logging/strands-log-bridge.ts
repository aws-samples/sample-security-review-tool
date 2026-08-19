import { configureLogging, type Logger } from "@strands-agents/sdk";
import { SrtLogger } from "./srt-logger.js";

const TAG = "strands-sdk";

/**
 * Routes Strands SDK diagnostics to the SRT log instead of letting the SDK's
 * default logger write warnings and transient errors directly to the terminal.
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
        warn: (...args) =>
            SrtLogger.logDebug(`${TAG} [warn]: ${formatArgs(args)}`),
        error: (...args) =>
            SrtLogger.logError(
                `${TAG}: ${formatArgs(args)}`,
                extractError(args),
            ),
    };
}

function formatArgs(args: unknown[]): string {
    return args.map(formatOne).join(" ");
}

function formatOne(value: unknown): string {
    if (value instanceof Error) return value.message;
    if (typeof value === "string") return value;
    try {
        return JSON.stringify(value);
    } catch {
        return String(value);
    }
}

function extractError(args: unknown[]): unknown {
    return (
        args.find((arg) => arg instanceof Error) ?? new Error(formatArgs(args))
    );
}
