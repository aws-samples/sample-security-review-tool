import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Contradiction } from "../../../rule-builder/src/requirements/requirements-contradictions.js";
import { RequirementsWorkflow } from "../../../rule-builder/src/requirements/requirements-workflow.js";
import { ScenarioResolver } from "../../../rule-builder/src/requirements/scenario-resolver.js";
import { RuleContext } from "../../../rule-builder/src/shared/rule-context.js";
import type { RuleRequirement } from "../../../rule-builder/src/shared/types/requirements.js";

const resolveTogether = vi.fn();

vi.mock("../../../rule-builder/src/requirements/scenario-resolver.js", () => ({
    ScenarioResolver: vi.fn(() => ({ resolveTogether })),
}));

interface TestableWorkflow {
    settleContradictions(
        requirements: RuleRequirement[],
    ): Promise<RuleRequirement[]>;
    detect(requirements: RuleRequirement[]): Promise<Contradiction[]>;
    resolveJointly(
        requirements: RuleRequirement[],
        contradictions: Contradiction[],
    ): Promise<RuleRequirement[]>;
}

function requirement(
    id: string,
    expectedBehavior: "flag" | "pass",
): RuleRequirement {
    return {
        id,
        decisionPointId: "DP-1",
        description: `configuration ${id}`,
        expectedBehavior,
        rationale: "the documented behavior decides the outcome",
        docReference: "https://docs.aws.amazon.com/example.html",
        settledBy: "documentation",
        evidence: "the documentation was consulted",
    };
}

function contradiction(firstId: string, secondId: string): Contradiction {
    return {
        ids: [firstId, secondId],
        sharedInput:
            "one template-time configuration satisfies both descriptions",
    };
}

function verdict(
    requirementId: string,
    expectedBehavior: "flag" | "pass",
    description: string | null,
) {
    return {
        requirementId,
        description,
        expectedBehavior,
        rationale: "the premise decides both outcomes",
        docReference: "https://docs.aws.amazon.com/example.html",
        settledBy: "documentation" as const,
        evidence: "the premise was answered from the documentation",
    };
}

function workflow(): TestableWorkflow {
    return new RequirementsWorkflow(
        new RuleContext(
            "AS-005",
            "autoscaling",
            "Auto Scaling groups must use launch templates",
        ),
    ) as unknown as TestableWorkflow;
}

describe("RequirementsWorkflow contradiction settlement", () => {
    it("resolves a contradiction that becomes visible only after the first pair is settled", async () => {
        const subject = workflow();
        const requirements = [
            requirement("REQ-02", "flag"),
            requirement("REQ-10", "flag"),
            requirement("REQ-12", "pass"),
        ];
        const firstPair = contradiction("REQ-10", "REQ-12");
        const exposedPair = contradiction("REQ-02", "REQ-12");
        const afterFirstResolution = requirements.map((item) =>
            item.id === "REQ-10"
                ? { ...item, rationale: "first pair was settled jointly" }
                : item,
        );
        const afterSecondResolution = afterFirstResolution.map((item) =>
            item.id === "REQ-02"
                ? { ...item, rationale: "exposed pair was settled jointly" }
                : item,
        );

        const detect = vi
            .spyOn(subject, "detect")
            .mockResolvedValueOnce([firstPair])
            .mockResolvedValueOnce([exposedPair])
            .mockResolvedValueOnce([]);
        const resolveJointly = vi
            .spyOn(subject, "resolveJointly")
            .mockResolvedValueOnce(afterFirstResolution)
            .mockResolvedValueOnce(afterSecondResolution);

        await expect(subject.settleContradictions(requirements)).resolves.toBe(
            afterSecondResolution,
        );
        expect(detect).toHaveBeenCalledTimes(3);
        expect(resolveJointly).toHaveBeenNthCalledWith(1, requirements, [
            firstPair,
        ]);
        expect(resolveJointly).toHaveBeenNthCalledWith(
            2,
            afterFirstResolution,
            [exposedPair],
        );
    });

    it("fails after three attempts when contradictions do not converge", async () => {
        const subject = workflow();
        const requirements = [
            requirement("REQ-01", "flag"),
            requirement("REQ-02", "pass"),
        ];
        const pair = contradiction("REQ-01", "REQ-02");

        const detect = vi.spyOn(subject, "detect").mockResolvedValue([pair]);
        const resolveJointly = vi
            .spyOn(subject, "resolveJointly")
            .mockImplementation(async (current) => current);

        await expect(
            subject.settleContradictions(requirements),
        ).rejects.toThrow(
            "still contradicts itself after 3 joint-resolution attempts: REQ-01 vs REQ-02",
        );
        expect(detect).toHaveBeenCalledTimes(4);
        expect(resolveJointly).toHaveBeenCalledTimes(3);
    });
});

describe("RequirementsWorkflow joint resolution", () => {
    beforeEach(() => {
        resolveTogether.mockReset();
        vi.mocked(ScenarioResolver).mockClear();
    });

    // Without this the descriptions never change, so the detector re-reports the
    // same pair every attempt and settlement can only converge by a verdict flip.
    it("narrows the description the joint resolution restates and keeps the one it returns null for", async () => {
        const subject = workflow();
        const requirements = [
            requirement("REQ-05", "pass"),
            requirement("REQ-09", "flag"),
        ];
        resolveTogether.mockResolvedValue({
            premise: "any attachment counts, whichever resource declares it",
            resolutions: [
                verdict(
                    "REQ-05",
                    "pass",
                    "no load balancer or target group attachment reaches the group by any means",
                ),
                verdict("REQ-09", "flag", null),
            ],
        });

        const settled = await subject.resolveJointly(requirements, [
            contradiction("REQ-05", "REQ-09"),
        ]);

        expect(settled.map((item) => item.description)).toEqual([
            "no load balancer or target group attachment reaches the group by any means",
            "configuration REQ-09",
        ]);
        expect(settled.map((item) => item.expectedBehavior)).toEqual([
            "pass",
            "flag",
        ]);
    });
});
