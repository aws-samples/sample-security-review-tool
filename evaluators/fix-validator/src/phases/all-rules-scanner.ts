import { Template } from 'cloudform-types';
import { allCloudFormationRules } from '../../../../src/assess/scanning/security-matrix/rules/index.js';
import type { BaseRule, Resource } from '../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import type { ScanResult } from '../../../../src/assess/scanning/base-scanner.js';

export function scanWithAllRules(template: Template, stackName: string): ScanResult[] {
    const results: ScanResult[] = [];

    if (!template.Resources) return results;

    for (const resourceId in template.Resources) {
        const resource: Resource = template.Resources[resourceId];

        const applicableRules = allCloudFormationRules.filter(rule => rule.appliesTo(resource.Type));

        for (const rule of applicableRules) {
            try {
                const result = evaluateRule(rule, stackName, template, resource, resourceId);
                if (result) results.push(result);
            } catch {
                // Skip rules that throw — we only care about findings, not crashes
            }
        }
    }

    return results;
}

function evaluateRule(rule: BaseRule, stackName: string, template: Template, resource: Resource, resourceId: string): ScanResult | null {
    const result = rule.evaluateResource(stackName, template, resource);

    if (result === undefined) {
        const cfResource = { Type: resource.Type, Properties: resource.Properties || {}, LogicalId: resourceId, Metadata: resource.Metadata };
        const allCfResources = Object.entries(template.Resources!).map(([id, res]: [string, any]) => ({ Type: res.Type, Properties: res.Properties || {}, LogicalId: id }));
        return rule.evaluate(cfResource, stackName, allCfResources);
    }

    return result;
}
