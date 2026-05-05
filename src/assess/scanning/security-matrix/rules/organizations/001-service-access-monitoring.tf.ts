import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfO001Rule extends BaseTerraformRule {
  constructor() {
    super('ORG-001', 'HIGH', 'Organizations lacks proper Service Control Policies (SCPs) to restrict service access', ['aws_organizations_organization']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_organizations_organization') {
      const featureSet = resource.values?.feature_set || 'ALL';
      if (featureSet === 'ALL') {
        const hasScps = allResources.some(r =>
          r.type === 'aws_organizations_policy' &&
          r.values?.type === 'SERVICE_CONTROL_POLICY'
        );

        if (!hasScps) {
          return this.createScanResult(resource, projectName, this.description, 'Add aws_organizations_policy with type = "SERVICE_CONTROL_POLICY" containing deny statements for organizations:EnableAWSServiceAccess.');
        }
      }
    }

    return null;
  }
}

export default new TfO001Rule();
