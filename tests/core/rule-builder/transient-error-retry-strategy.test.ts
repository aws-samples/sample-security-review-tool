import {
    type AfterModelCallEvent,
    BeforeModelCallEvent,
    type LocalAgent,
    ModelError,
    ModelStreamUpdateEvent,
    ModelThrottledError,
    type RetryDecision,
} from "@strands-agents/sdk";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TransientErrorRetryStrategy } from "../../../rule-builder/src/shared/agents/transient-error-retry-strategy.js";
import { SrtLogger } from "../../../src/shared/logging/srt-logger.js";

class TestRetryStrategy extends TransientErrorRetryStrategy {
    public isErrorRetryable(error: Error): boolean {
        return this.isRetryable(error);
    }

    public retryDecision(event: AfterModelCallEvent): RetryDecision {
        return this.computeRetryDecision(event);
    }
}

describe("TransientErrorRetryStrategy", () => {
    let strategy: TestRetryStrategy;

    beforeEach(() => {
        strategy = new TestRetryStrategy();
    });

    it.each([
        "InternalServerException",
        "ModelErrorException",
        "ModelNotReadyException",
        "ModelStreamErrorException",
        "ModelTimeoutException",
        "ServiceUnavailableException",
        "ThrottlingException",
    ])("retries a wrapped %s", (errorName) => {
        const cause = Object.assign(new Error("temporary Bedrock failure"), {
            name: errorName,
        });
        const error = new ModelError(cause.message, { cause });

        expect(strategy.isErrorRetryable(error)).toBe(true);
    });

    it("retains the SDK throttling retry behavior", () => {
        expect(
            strategy.isErrorRetryable(new ModelThrottledError("slow down")),
        ).toBe(true);
    });

    it("retries a stream that ends without a terminal message", () => {
        expect(
            strategy.isErrorRetryable(
                new ModelError("Stream ended without completing a message"),
            ),
        ).toBe(true);
    });

    it.each([
        "ValidationException",
        "AccessDeniedException",
        "ResourceNotFoundException",
    ])("does not retry a wrapped %s", (errorName) => {
        const cause = Object.assign(new Error("request rejected"), {
            name: errorName,
        });
        const error = new ModelError(cause.message, { cause });

        expect(strategy.isErrorRetryable(error)).toBe(false);
    });

    it("logs the streamed tool and retry decision", () => {
        const hooks = new Map<unknown, (event: unknown) => void>();
        const agent = {
            id: "agent-123",
            addHook: (
                eventType: unknown,
                callback: (event: unknown) => void,
            ) => {
                hooks.set(eventType, callback);
                return () => {};
            },
            toolRegistry: {
                list: () => [{ name: "write_file" }, { name: "run_vitest" }],
            },
        } as unknown as LocalAgent;
        strategy.initAgent(agent);

        hooks.get(BeforeModelCallEvent)?.({});
        hooks.get(ModelStreamUpdateEvent)?.({
            event: {
                type: "modelContentBlockStartEvent",
                start: {
                    type: "toolUseStart",
                    name: "write_file",
                    toolUseId: "tool-456",
                },
            },
        });
        hooks.get(ModelStreamUpdateEvent)?.({
            event: {
                type: "modelContentBlockDeltaEvent",
                delta: {
                    type: "toolUseInputDelta",
                    input: '{"filePath":',
                },
            },
        });

        const error = new ModelError(
            "Stream ended without completing a message",
            { cause: new SyntaxError("Expected '}'") },
        );
        const logError = vi
            .spyOn(SrtLogger, "logError")
            .mockImplementation(() => {});
        const decision = strategy.retryDecision({
            agent,
            model: { modelId: "global.anthropic.claude-opus-5" },
            attemptCount: 1,
            error,
        } as AfterModelCallEvent);

        expect(decision.retry).toBe(true);
        expect(logError).toHaveBeenCalledWith(
            "Rule builder model call failed; retrying",
            error,
            expect.objectContaining({
                agentId: "agent-123",
                modelId: "global.anthropic.claude-opus-5",
                attemptCount: 1,
                maxAttempts: 3,
                retry: true,
                toolName: "write_file",
                toolUseId: "tool-456",
                toolInputCharacters: 12,
                availableTools: ["write_file", "run_vitest"],
            }),
        );
    });
});
