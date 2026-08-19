import { beforeEach, describe, expect, it, vi } from "vitest";
import { SrtLogger } from "../../../src/shared/logging/srt-logger.js";

const { configureLogging } = vi.hoisted(() => ({
    configureLogging: vi.fn(),
}));

vi.mock("@strands-agents/sdk", () => ({ configureLogging }));

describe("Strands log bridge", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("routes SDK errors to the SRT log without writing to the terminal", async () => {
        const logError = vi
            .spyOn(SrtLogger, "logError")
            .mockImplementation(() => {});
        const consoleError = vi
            .spyOn(console, "error")
            .mockImplementation(() => {});
        const { bridgeStrandsLoggingToSrt } = await import(
            "../../../src/shared/logging/strands-log-bridge.js"
        );

        bridgeStrandsLoggingToSrt();
        const logger = configureLogging.mock.calls[0]?.[0];
        const error = new SyntaxError("Expected '}'");
        logger.error("unable to parse tool input JSON", error);

        expect(consoleError).not.toHaveBeenCalled();
        expect(logError).toHaveBeenCalledWith(
            "strands-sdk: unable to parse tool input JSON Expected '}'",
            error,
        );
    });
});
