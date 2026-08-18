import { ModelError } from "@strands-agents/sdk";
import { describe, expect, it } from "vitest";
import {
    describeErrorChain,
    formatErrorSummary,
} from "../../../src/shared/error-handling/error-diagnostics.js";

describe("error diagnostics", () => {
    it("captures the wrapped Bedrock cause and AWS request metadata", () => {
        const bedrockError = Object.assign(
            new Error("Bedrock is unable to process your request."),
            {
                name: "ModelStreamErrorException",
                originalStatusCode: 500,
                originalMessage:
                    "The upstream model failed while generating a response.",
                $fault: "client",
                $metadata: {
                    httpStatusCode: 424,
                    requestId: "request-123",
                    attempts: 2,
                    totalRetryDelay: 4000,
                },
            },
        );
        const error = new ModelError(bedrockError.message, {
            cause: bedrockError,
        });

        expect(describeErrorChain(error)).toMatchObject([
            {
                name: "ModelError",
                message: "Bedrock is unable to process your request.",
            },
            {
                name: "ModelStreamErrorException",
                message: "Bedrock is unable to process your request.",
                fault: "client",
                originalStatusCode: 500,
                originalMessage:
                    "The upstream model failed while generating a response.",
                metadata: {
                    httpStatusCode: 424,
                    requestId: "request-123",
                    attempts: 2,
                    totalRetryDelay: 4000,
                },
            },
        ]);
    });

    it("includes provider diagnostics in the console summary", () => {
        const cause = Object.assign(new Error("Bedrock failed."), {
            name: "ModelErrorException",
            originalStatusCode: 500,
            $metadata: {
                httpStatusCode: 424,
                requestId: "request-456",
            },
        });

        expect(
            formatErrorSummary(new Error("Agent failed.", { cause })),
        ).toContain(
            "caused by ModelErrorException: Bedrock failed. (HTTP 424, original status 500, request request-456)",
        );
    });
});
