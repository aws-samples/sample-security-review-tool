import { CloudFormationResource } from "./security-rule-base.js";

export interface ResolvedValue<T = any> {
    value: T | null;
    isResolved: boolean;
    isIntrinsicFunction: boolean;
    referencedResources: string[];
}

export interface ResolveOptions {
    treatLiteralStringsAs?: 'external-references';
}

export class CloudFormationResolver {
    private resources: Record<string, any> = {};

    constructor(resources?: CloudFormationResource[]) {
        const template: { Resources: Record<string, any> } = { Resources: {} };

        resources?.forEach(r => {
            template.Resources[r.LogicalId] = { Type: r.Type, Properties: r.Properties };
        });

        this.resources = template.Resources || {};
    }

    public resolve<T = any>(value: any, options?: ResolveOptions): ResolvedValue<T> {
        return this.resolveValue(value, options || {});
    }

    public getResource(logicalId: string): any | null {
        return this.resources[logicalId] || null;
    }

    public getResourcesByType(type: string): any[] {
        return Object.entries(this.resources)
            .filter(([_, resource]) => resource.Type === type)
            .map(([logicalId, resource]) => ({
                ...resource,
                LogicalId: logicalId
            }));
    }

    private resolveValue<T>(value: any, options: ResolveOptions): ResolvedValue<T> {
        // Simple values
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' || value === null) {
            return this.resolveSimpleValue(value, options) as ResolvedValue<T>;
        }

        // Arrays
        if (Array.isArray(value)) {
            return this.resolveArray(value, options) as ResolvedValue<T>;
        }

        // Objects (intrinsic functions)
        if (value && typeof value === 'object') {
            return this.resolveObject(value, options) as ResolvedValue<T>;
        }

        return {
            value: null,
            isResolved: false,
            isIntrinsicFunction: false,
            referencedResources: []
        };
    }

    private resolveSimpleValue<T>(value: any, options: ResolveOptions): ResolvedValue<T> {
        // Handle strings based on options
        if (typeof value === 'string') {
            if (options.treatLiteralStringsAs === 'external-references') {
                return {
                    value: null,
                    isResolved: false,
                    isIntrinsicFunction: false,
                    referencedResources: []
                };
            }
        }

        // Default: simple values are resolved as-is
        return {
            value: value as T,
            isResolved: true,
            isIntrinsicFunction: false,
            referencedResources: []
        };
    }

    private resolveArray<T>(value: any[], options: ResolveOptions): ResolvedValue<T> {
        const resolved = value.map(item => this.resolveValue(item, options));
        const allResolved = resolved.every(r => r.isResolved);
        const allRefs = resolved.flatMap(r => r.referencedResources);

        return {
            value: allResolved ? resolved.map(r => r.value) as T : null,
            isResolved: allResolved,
            isIntrinsicFunction: false,
            referencedResources: allRefs
        };
    }

    private resolveObject<T>(value: any, options: ResolveOptions): ResolvedValue<T> {
        // !Ref
        if (value.Ref) {
            return {
                value: value.Ref as T,
                isResolved: this.resources[value.Ref] !== undefined,
                isIntrinsicFunction: true,
                referencedResources: [value.Ref]
            };
        }

        // !GetAtt
        if (value['Fn::GetAtt']) {
            const [resourceId] = Array.isArray(value['Fn::GetAtt']) ? value['Fn::GetAtt'] : [value['Fn::GetAtt']];

            return {
                value: null,
                isResolved: false,
                isIntrinsicFunction: true,
                referencedResources: [resourceId]
            };
        }

        // Check for other CloudFormation intrinsic functions
        const intrinsicFunctions = [
            'Fn::If', 'Fn::Equals', 'Fn::And', 'Fn::Or', 'Fn::Not',
            'Fn::Sub', 'Fn::Join', 'Fn::Split', 'Fn::Select',
            'Fn::Base64', 'Fn::GetAZs', 'Fn::ImportValue', 'Fn::FindInMap'
        ];

        const hasIntrinsicFunction = intrinsicFunctions.some(fn => value.hasOwnProperty(fn));

        if (hasIntrinsicFunction) {
            // Other functions - just extract references
            const refs = this.extractReferences(value);
            return {
                value: null,
                isResolved: false,
                isIntrinsicFunction: true,
                referencedResources: refs
            };
        }

        // Handle regular objects (not intrinsic functions)
        // Recursively resolve all properties of the object
        const resolvedObject: any = {};
        const allRefs: string[] = [];
        let allResolved = true;

        for (const [key, val] of Object.entries(value)) {
            const resolved = this.resolveValue(val, options);
            resolvedObject[key] = resolved.value;
            allRefs.push(...resolved.referencedResources);

            if (!resolved.isResolved) {
                allResolved = false;
            }
        }

        return {
            value: allResolved ? resolvedObject as T : null,
            isResolved: allResolved,
            isIntrinsicFunction: false,
            referencedResources: allRefs
        };
    }

    private extractReferences(obj: any): string[] {
        const refs: string[] = [];

        if (obj && typeof obj === 'object') {
            if (obj.Ref) {
                refs.push(obj.Ref);
            }

            if (obj['Fn::GetAtt']) {
                const [resourceId] = Array.isArray(obj['Fn::GetAtt'])
                    ? obj['Fn::GetAtt']
                    : [obj['Fn::GetAtt']];
                refs.push(resourceId);
            }

            // Recursively check other properties
            for (const value of Object.values(obj)) {
                if (Array.isArray(value)) {
                    value.forEach(item => refs.push(...this.extractReferences(item)));
                } else {
                    refs.push(...this.extractReferences(value));
                }
            }
        }

        return refs;
    }
}
