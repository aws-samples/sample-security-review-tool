import { describe, expect, it } from "vitest";
import type {
    ScanResult,
    TerraformResource,
    TfContext,
} from "../../../../../../../src/assess/scanning/security-matrix/controls/types.js";
import type { As005Adapter } from "../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js";
import { As005TfAdapterFactory } from "../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js";
import { as005Control } from "../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js";

const factory = new As005TfAdapterFactory();

function buildResource(values: Record<string, unknown>): TerraformResource {
    return {
        type: "aws_autoscaling_group",
        name: "asg",
        address: "aws_autoscaling_group.asg",
        values,
    } as TerraformResource;
}

function run(values: Record<string, unknown>): ScanResult | null {
    const resource = buildResource(values);
    const context: TfContext = {
        projectName: "test-project",
        resource,
        allResources: [resource],
    };
    const adapter = factory.bind(context) as As005Adapter;
    return as005Control.run(adapter, context);
}

describe("AS-005 (Terraform) — Auto Scaling group must use a launch template", () => {
    // Primary behavior owned by REQ-06: no launch source declared at all must be flagged,
    // because EC2 Auto Scaling supplies no default launch source.
    it("flags an Auto Scaling group with no launch_configuration, no launch_template block, and no mixed_instances_policy block", () => {
        const result = run({
            min_size: 1,
            max_size: 3,
            availability_zones: ["us-east-1a"],
        });

        expect(result).not.toBeNull();
        expect(result?.check_id).toBe("AS-005");
        expect(result?.resourceName).toBe("aws_autoscaling_group.asg");
        expect(result?.resourceType).toBe("aws_autoscaling_group");
    });

    // Opposite outcome: the nearest input that flips the verdict — a launch_template block is present.
    it("does not flag an otherwise identical group that declares a launch_template block", () => {
        const result = run({
            min_size: 1,
            max_size: 3,
            availability_zones: ["us-east-1a"],
            launch_template: [{ id: "aws_launch_template.lt" }],
        });

        expect(result).toBeNull();
    });

    it("flags a group whose dynamic launch_template block can never emit an instance", () => {
        const result = run({
            min_size: 1,
            max_size: 3,
            dynamic: {
                launch_template: [
                    {
                        for_each: [],
                        content: [
                            {
                                id: "aws_launch_template.lt",
                                version: "$Latest",
                            },
                        ],
                    },
                ],
            },
        });

        expect(result).not.toBeNull();
        expect(result?.issue).toContain(
            "declares no instance configuration source",
        );
    });
});
