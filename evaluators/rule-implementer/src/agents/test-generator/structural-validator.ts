import { yamlParse } from 'yaml-cfn';
import { FixtureFormat } from '../../shared/types/rule-catalog.js';

export interface StructuralValidation {
    valid: boolean;
    error?: string;
    resourceTypes: string[];
}

export function validateFixtureStructure(templateSnippet: string, applicableResourceTypes: string[], fixtureFormat: FixtureFormat): StructuralValidation {
    if (fixtureFormat === 'terraform') {
        return validateTerraformStructure(templateSnippet, applicableResourceTypes);
    }
    return validateCloudFormationStructure(templateSnippet, applicableResourceTypes);
}

function validateCloudFormationStructure(snippet: string, applicableResourceTypes: string[]): StructuralValidation {
    let parsed: Record<string, any>;
    try {
        parsed = yamlParse(snippet);
    } catch (error) {
        return { valid: false, error: `YAML parse error: ${(error as Error).message}`, resourceTypes: [] };
    }

    if (!parsed || typeof parsed !== 'object') {
        return { valid: false, error: 'Parsed template is not an object', resourceTypes: [] };
    }

    const resources = parsed.Resources ?? parsed;
    if (!resources || typeof resources !== 'object') {
        return { valid: false, error: 'No resources found in template', resourceTypes: [] };
    }

    const resourceTypes: string[] = [];
    for (const [_, resource] of Object.entries(resources)) {
        if (resource && typeof resource === 'object' && 'Type' in resource) {
            resourceTypes.push((resource as any).Type);
        }
    }

    if (resourceTypes.length === 0) {
        return { valid: false, error: 'Template contains no typed resources', resourceTypes: [] };
    }

    const hasTargetResource = resourceTypes.some(type => applicableResourceTypes.includes(type));
    if (!hasTargetResource) {
        return {
            valid: false,
            error: `Fixture must include at least one resource of type [${applicableResourceTypes.join(', ')}] but only contains [${resourceTypes.join(', ')}]`,
            resourceTypes,
        };
    }

    return { valid: true, resourceTypes };
}

function validateTerraformStructure(snippet: string, applicableResourceTypes: string[]): StructuralValidation {
    let parsed: unknown;
    try {
        parsed = JSON.parse(snippet);
    } catch (error) {
        return { valid: false, error: `JSON parse error: ${(error as Error).message}`, resourceTypes: [] };
    }

    const resources = Array.isArray(parsed) ? parsed : [parsed];
    const resourceTypes: string[] = [];

    for (const resource of resources) {
        if (resource && typeof resource === 'object' && 'type' in resource) {
            resourceTypes.push((resource as any).type);
        }
    }

    if (resourceTypes.length === 0) {
        return { valid: false, error: 'No typed resources found in fixture', resourceTypes: [] };
    }

    const hasTargetResource = resourceTypes.some(type => applicableResourceTypes.includes(type));
    if (!hasTargetResource) {
        return {
            valid: false,
            error: `Fixture must include at least one resource of type [${applicableResourceTypes.join(', ')}] but only contains [${resourceTypes.join(', ')}]`,
            resourceTypes,
        };
    }

    return { valid: true, resourceTypes };
}
