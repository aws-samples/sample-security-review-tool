import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ConversionCheckpointStore } from "../../../rule-builder/src/converting/conversion-checkpoint-store.js";

describe("ConversionCheckpointStore", () => {
    let stateRootFolderPath: string;

    beforeEach(() => {
        stateRootFolderPath = fs.mkdtempSync(
            path.join(os.tmpdir(), "conversion-checkpoint-"),
        );
    });

    afterEach(() => {
        fs.rmSync(stateRootFolderPath, { recursive: true, force: true });
    });

    it("returns a rewritten description saved for the same source description", () => {
        const store = new ConversionCheckpointStore(
            "API-GW-002",
            "api-gateway",
            stateRootFolderPath,
        );

        store.write(
            "X-Ray tracing not enabled",
            "Lambda functions must have X-Ray tracing enabled",
        );

        expect(store.read("X-Ray tracing not enabled")).toBe(
            "Lambda functions must have X-Ray tracing enabled",
        );
    });

    it("does not reuse a rewrite when the legacy description has changed", () => {
        const store = new ConversionCheckpointStore(
            "AS-005",
            "autoscaling",
            stateRootFolderPath,
        );

        store.write(
            "Auto Scaling Group does not use a launch template",
            "Auto Scaling groups must use launch templates",
        );

        expect(store.read("A newer legacy description")).toBeNull();
    });

    it("removes the checkpoint after the conversion completes", () => {
        const store = new ConversionCheckpointStore(
            "AS-005",
            "autoscaling",
            stateRootFolderPath,
        );
        store.write(
            "Auto Scaling Group does not use a launch template",
            "Auto Scaling groups must use launch templates",
        );

        store.remove();

        expect(
            store.read("Auto Scaling Group does not use a launch template"),
        ).toBeNull();
    });
});
