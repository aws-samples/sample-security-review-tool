import { describe, expect, it } from "vitest";
import type {
    TerraformResource,
    TfContext,
} from "../../../../../../../src/assess/scanning/security-matrix/controls/types.js";
import { As005TfAdapterFactory } from "../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js";
import { as005Control } from "../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js";

const factory = new As005TfAdapterFactory();

const unresolved = (expression: string): string =>
    `__unresolved__:${expression}`;

function buildContext(values: Record<string, unknown>): TfContext {
    const resource: TerraformResource = {
        type: "aws_autoscaling_group",
        name: "app",
        address: "aws_autoscaling_group.app",
        values: { min_size: 1, max_size: 2, ...values },
    } as TerraformResource;

    return { projectName: "test-project", resource, allResources: [resource] };
}

function run(values: Record<string, unknown>) {
    const context = buildContext(values);
    return as005Control.run(factory.bind(context), context);
}

describe("AS-005 Terraform - launch template identifier only known at deployment time (REQ-11)", () => {
    it("passes when the launch_template id comes from a variable with no reachable default", () => {
        const result = run({
            launch_template: [
                {
                    id: unresolved("var.launch_template_id"),
                    version: "$Latest",
                },
            ],
        });

        expect(result).toBeNull();
    });

    it("passes when the launch_template name comes from an unresolved local value", () => {
        const result = run({
            launch_template: [
                {
                    name: unresolved("local.launch_template_name"),
                    version: "$Latest",
                },
            ],
        });

        expect(result).toBeNull();
    });

    it("passes when the launch_template id is a resolved resource reference", () => {
        const result = run({
            launch_template: [
                { id: "aws_launch_template.lt", version: "$Latest" },
            ],
        });

        expect(result).toBeNull();
    });

    it("passes a source-parsed dynamic launch_template block with an unresolved condition", () => {
        const result = run({
            dynamic: {
                launch_template: [
                    {
                        for_each: unresolved(
                            "var.use_mixed_instances_policy ? [] : [1]",
                        ),
                        content: [
                            {
                                id: unresolved("local.launch_template_id"),
                                version: unresolved(
                                    "local.launch_template_version",
                                ),
                            },
                        ],
                    },
                ],
            },
        });

        expect(result).toBeNull();
    });

    // Opposite outcome: the primary behaviour (flagging a launch configuration) is owned by
    // the base requirement of AS-005. Only the provisioning mechanism changes here.
    it("flags the group when it names a launch configuration instead of a launch template", () => {
        const result = run({
            launch_configuration: "app-launch-configuration",
        });

        expect(result).not.toBeNull();
        expect(result?.check_id).toBe("AS-005");
        expect(result?.resourceName).toBe("aws_autoscaling_group.app");
        expect(result?.issue).toContain("launch configuration");
    });
});
