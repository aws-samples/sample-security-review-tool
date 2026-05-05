import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfCognito001Rule extends BaseTerraformRule {
  constructor() {
    super('COGNITO-001', 'HIGH', 'Cognito Identity Pool allows unauthenticated access without proper restrictions', ['aws_cognito_identity_pool']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_cognito_identity_pool') {
      const allowUnauthenticated = resource.values?.allow_unauthenticated_identities;
      if (allowUnauthenticated === true) {
        return this.createScanResult(resource, projectName, this.description, 'Set allow_unauthenticated_identities = false or ensure the unauthenticated IAM role has minimal permissions.');
      }
    }

    return null;
  }
}

export default new TfCognito001Rule();
