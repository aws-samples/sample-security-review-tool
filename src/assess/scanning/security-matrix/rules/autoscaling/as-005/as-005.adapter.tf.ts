import type { AdapterFactory, TfContext } from "../../../controls/types.js";
import type { As005Adapter } from "./as-005.adapter.js";

const LAUNCH_TEMPLATE_IDENTIFIERS = ["id", "name"] as const;
const MIXED_POLICY_TEMPLATE_IDENTIFIERS = [
    "launch_template_id",
    "launch_template_name",
] as const;

export class As005TfAdapterFactory implements AdapterFactory<TfContext> {
    readonly applicableResourceTypes = ["aws_autoscaling_group"];

    appliesTo(resourceType: string): boolean {
        return this.applicableResourceTypes.includes(resourceType);
    }

    bind(context: TfContext): As005TfAdapter {
        return new As005TfAdapter(context);
    }
}

class As005TfAdapter implements As005Adapter {
    readonly resourceId: string;
    readonly resourceType: string;

    constructor(private readonly ctx: TfContext) {
        this.resourceId = ctx.resource.address;
        this.resourceType = ctx.resource.type;
    }

    /**
     * A named launch configuration is a launch configuration whatever the name turns out to be,
     * so a value only known at deployment time still counts as one.
     */
    usesLaunchConfiguration(): boolean {
        return this.isPresent(this.value("launch_configuration"));
    }

    declaresLaunchTemplateReference(): boolean {
        return this.hasBlock(this.values(), "launch_template");
    }

    usesLaunchTemplate(): boolean {
        return this.blocks(this.values(), "launch_template").some((block) =>
            this.identifiesTemplate(block, LAUNCH_TEMPLATE_IDENTIFIERS),
        );
    }

    hasMixedInstancesPolicy(): boolean {
        return this.hasBlock(this.values(), "mixed_instances_policy");
    }

    mixedInstancesPolicyUsesLaunchTemplate(): boolean {
        return this.blocks(this.values(), "mixed_instances_policy").some(
            (policy) => {
                if (!this.isRecord(policy)) return true;

                return this.blocks(policy, "launch_template").some(
                    (launchTemplate) => {
                        if (!this.isRecord(launchTemplate)) return true;

                        return this.blocks(
                            launchTemplate,
                            "launch_template_specification",
                        ).some((specification) =>
                            this.identifiesTemplate(
                                specification,
                                MIXED_POLICY_TEMPLATE_IDENTIFIERS,
                            ),
                        );
                    },
                );
            },
        );
    }

    /** An Auto Scaling group cannot be based on an existing instance identifier in Terraform. */
    usesExistingInstance(): boolean {
        return false;
    }

    private identifiesTemplate(
        block: unknown,
        identifiers: readonly string[],
    ): boolean {
        if (!this.isRecord(block)) return true;
        return identifiers.some((key) => this.isPresent(block[key]));
    }

    private hasBlock(
        container: Record<string, unknown>,
        name: string,
    ): boolean {
        return this.blocks(container, name).length > 0;
    }

    private blocks(
        container: Record<string, unknown>,
        name: string,
    ): unknown[] {
        return [
            ...this.entries(container[name]),
            ...this.dynamicBlocks(container, name),
        ];
    }

    private dynamicBlocks(
        container: Record<string, unknown>,
        name: string,
    ): unknown[] {
        const dynamic = container.dynamic;
        if (!this.isRecord(dynamic)) return [];

        return this.entries(dynamic[name]).flatMap((declaration) => {
            if (!this.isRecord(declaration)) return [declaration];
            if (!this.mayEmit(declaration.for_each)) return [];
            return this.entries(declaration.content);
        });
    }

    private mayEmit(forEach: unknown): boolean {
        if (Array.isArray(forEach)) return forEach.length > 0;
        if (this.isRecord(forEach)) return Object.keys(forEach).length > 0;
        return forEach !== null && forEach !== undefined;
    }

    private entries(value: unknown): unknown[] {
        if (value === undefined || value === null) return [];
        return Array.isArray(value) ? value : [value];
    }

    private isRecord(value: unknown): value is Record<string, unknown> {
        return (
            typeof value === "object" && value !== null && !Array.isArray(value)
        );
    }

    private isPresent(value: unknown): boolean {
        if (value === undefined || value === null) return false;
        if (typeof value === "string") return value.trim().length > 0;
        return true;
    }

    private value(name: string): unknown {
        return this.values()[name];
    }

    private values(): Record<string, unknown> {
        return (
            (this.ctx.resource.values as Record<string, unknown> | undefined) ??
            {}
        );
    }
}
