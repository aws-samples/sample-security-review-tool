import { ModelError, ModelThrottledError } from "@strands-agents/sdk";
import { describe, expect, it } from "vitest";
import { TransientErrorRetryStrategy } from "../../../rule-builder/src/shared/agents/transient-error-retry-strategy.js";

class TestRetryStrategy extends TransientErrorRetryStrategy {
    public isErrorRetryable(error: Error): boolean {
        return this.isRetryable(error);
    }
}

describe("TransientErrorRetryStrategy", () => {
    const strategy = new TestRetryStrategy();

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
});
