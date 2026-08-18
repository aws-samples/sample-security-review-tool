import { describe, expect, it } from "vitest";
import type {
    TerraformResource,
    TfContext,
} from "../../../../../../../src/assess/scanning/security-matrix/controls/types.js";
import { As005TfAdapterFactory } from "../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js";
import { as005Control } from "../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js";

const factory = new As005TfAdapterFactory();

function scan(resource: TerraformResource) {
    const context: TfContext = {
        projectName: "test-project",
        resource,
        allResources: [resource],
    };
    return as005Control.run(factory.bind(context), context);
}

function groupWithMixedInstancesPolicy(
    launchTemplateId: unknown,
): TerraformResource {
    return {
        type: "aws_autoscaling_group",
        name: "app",
        address: "aws_autoscaling_group.app",
        values: {
            min_size: 1,
            max_size: 2,
            mixed_instances_policy: [
                {
                    launch_template: [
                        {
                            launch_template_specification: [
                                {
                                    launch_template_id: launchTemplateId,
                                    version: "$Latest",
                                },
                            ],
                        },
                    ],
                },
            ],
        },
    } as unknown as TerraformResource;
}

describe("AS-005 Terraform — mixed instances policy launch template identifier from a deployment-time input", () => {
    // Primary behavior owned by this requirement: a mixed instances policy can only
    // reference a launch template, so an identifier only known at deploy time still passes.
    it("passes when the mixed instances policy launch template id comes from a variable with no reachable default", () => {
        const result = scan(
            groupWithMixedInstancesPolicy(
                "__unresolved__:var.launch_template_id",
            ),
        );

        expect(result).toBeNull();
    });

    it("passes when the mixed instances policy launch template id comes from a data source lookup", () => {
        const result = scan(
            groupWithMixedInstancesPolicy(
                "__unresolved__:data.aws_launch_template.chosen.id",
            ),
        );

        expect(result).toBeNull();
    });

    it("passes a source-parsed dynamic mixed_instances_policy with a launch template", () => {
        const result = scan({
            type: "aws_autoscaling_group",
            name: "app",
            address: "aws_autoscaling_group.app",
            values: {
                dynamic: {
                    mixed_instances_policy: [
                        {
                            for_each:
                                "__unresolved__:var.use_mixed_instances_policy ? [var.mixed_instances_policy] : []",
                            content: [
                                {
                                    dynamic: {
                                        launch_template: [
                                            {
                                                for_each: [
                                                    "__unresolved__:mixed_instances_policy.value.launch_template",
                                                ],
                                                content: [
                                                    {
                                                        launch_template_specification:
                                                            [
                                                                {
                                                                    launch_template_id:
                                                                        "__unresolved__:local.launch_template_id",
                                                                    version:
                                                                        "__unresolved__:local.launch_template_version",
                                                                },
                                                            ],
                                                    },
                                                ],
                                            },
                                        ],
                                    },
                                },
                            ],
                        },
                    ],
                },
            },
        } as unknown as TerraformResource);

        expect(result).toBeNull();
    });

    // Opposite outcome: the identifier is still present but names no launch template,
    // so the group is not provably launched from a launch template.
    it("flags a mixed instances policy whose launch template id is present but empty", () => {
        const result = scan(groupWithMixedInstancesPolicy("   "));

        expect(result).not.toBeNull();
        expect(result?.check_id).toBe("AS-005");
        expect(result?.issue).toContain("mixed instances policy");
    });
});
