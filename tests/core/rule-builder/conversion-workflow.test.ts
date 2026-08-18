import { afterEach, describe, expect, it, vi } from "vitest";
import { BuildWorkflow } from "../../../rule-builder/src/building/build-workflow.js";
import { ConversionCheckpointStore } from "../../../rule-builder/src/converting/conversion-checkpoint-store.js";
import { ConversionWorkflow } from "../../../rule-builder/src/converting/conversion-workflow.js";
import { DescriptionRewriter } from "../../../rule-builder/src/converting/description-rewriter.js";
import {
    type LegacyRule,
    LegacyRuleReader,
} from "../../../rule-builder/src/converting/legacy-rule-reader.js";
import { LegacyRuleRemover } from "../../../rule-builder/src/converting/legacy-rule-remover.js";
import { RuleContext } from "../../../rule-builder/src/shared/rule-context.js";
import {
    RuleLocator,
    RuleNotFoundError,
} from "../../../rule-builder/src/shared/rule-locator.js";

const LEGACY: LegacyRule = {
    ruleId: "AS-005",
    service: "autoscaling",
    description: "Auto Scaling Group does not use a launch template",
    sourceFilePaths: ["/tmp/as-005.cf.ts", "/tmp/as-005.tf.ts"],
};

afterEach(() => {
    vi.restoreAllMocks();
});

describe("ConversionWorkflow resume behavior", () => {
    it("uses existing converted requirements even while the legacy rule still exists", async () => {
        const converted = new RuleContext(
            "AS-005",
            "autoscaling",
            "Auto Scaling groups must use launch templates",
        );
        vi.spyOn(LegacyRuleReader.prototype, "read").mockResolvedValue(LEGACY);
        vi.spyOn(RuleLocator.prototype, "locate").mockReturnValue(converted);
        const rewrite = vi.spyOn(DescriptionRewriter.prototype, "rewrite");
        const removeLegacy = vi
            .spyOn(LegacyRuleRemover.prototype, "remove")
            .mockReturnValue([]);
        vi.spyOn(
            ConversionCheckpointStore.prototype,
            "remove",
        ).mockReturnValue();
        const build = vi
            .spyOn(BuildWorkflow.prototype, "run")
            .mockImplementation(async (options) => {
                await options.afterImplementation?.();
            });

        await new ConversionWorkflow("AS-005").run();

        expect(rewrite).not.toHaveBeenCalled();
        expect(removeLegacy).toHaveBeenCalledOnce();
        expect(
            (build.mock.instances[0] as unknown as { context: RuleContext })
                .context,
        ).toBe(converted);
    });

    it("reuses a checkpointed description after a requirements-phase failure", async () => {
        vi.spyOn(LegacyRuleReader.prototype, "read").mockResolvedValue(LEGACY);
        vi.spyOn(RuleLocator.prototype, "locate").mockImplementation(() => {
            throw new RuleNotFoundError("not built yet");
        });
        vi.spyOn(ConversionCheckpointStore.prototype, "read").mockReturnValue(
            "Auto Scaling groups must use launch templates",
        );
        const removeCheckpoint = vi.spyOn(
            ConversionCheckpointStore.prototype,
            "remove",
        );
        const rewrite = vi.spyOn(DescriptionRewriter.prototype, "rewrite");
        const build = vi
            .spyOn(BuildWorkflow.prototype, "run")
            .mockRejectedValue(new Error("requirements failed"));

        await expect(new ConversionWorkflow("AS-005").run()).rejects.toThrow(
            "requirements failed",
        );

        expect(rewrite).not.toHaveBeenCalled();
        expect(removeCheckpoint).not.toHaveBeenCalled();
        expect(
            (build.mock.instances[0] as unknown as { context: RuleContext })
                .context.description,
        ).toBe("Auto Scaling groups must use launch templates");
    });

    it("saves a new rewritten description before starting the build", async () => {
        vi.spyOn(LegacyRuleReader.prototype, "read").mockResolvedValue(LEGACY);
        vi.spyOn(RuleLocator.prototype, "locate").mockImplementation(() => {
            throw new RuleNotFoundError("not built yet");
        });
        vi.spyOn(ConversionCheckpointStore.prototype, "read").mockReturnValue(
            null,
        );
        const writeCheckpoint = vi.spyOn(
            ConversionCheckpointStore.prototype,
            "write",
        );
        vi.spyOn(DescriptionRewriter.prototype, "rewrite").mockResolvedValue(
            "Auto Scaling groups must use launch templates",
        );
        vi.spyOn(BuildWorkflow.prototype, "run").mockRejectedValue(
            new Error("requirements failed"),
        );

        await expect(new ConversionWorkflow("AS-005").run()).rejects.toThrow(
            "requirements failed",
        );

        expect(writeCheckpoint).toHaveBeenCalledWith(
            LEGACY.description,
            "Auto Scaling groups must use launch templates",
        );
    });
});
