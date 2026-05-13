import { Template } from 'cloudform-types';
import { yamlParse } from 'yaml-cfn';
import type { TerraformResource } from '../../../../../src/assess/scanning/security-matrix/terraform-rule-base.js';

export function buildCloudFormationTemplate(snippet: string): Template {
    const parsed = yamlParse(snippet);

    if (parsed?.AWSTemplateFormatVersion || parsed?.Resources) {
        return parsed as Template;
    }

    return {
        AWSTemplateFormatVersion: '2010-09-09',
        Description: 'Requirement validation fixture',
        Resources: parsed,
    } as Template;
}

export function buildTerraformResources(snippet: string): TerraformResource[] {
    const parsed = JSON.parse(snippet);

    if (Array.isArray(parsed)) return parsed;

    if (parsed.type && parsed.values) return [parsed];

    return Object.entries(parsed).map(([address, resource]: [string, any]) => ({
        type: resource.type,
        name: resource.name ?? address.split('.').pop() ?? address,
        address,
        values: resource.values ?? {},
    }));
}
