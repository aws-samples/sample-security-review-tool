import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSl001Rule extends BaseTerraformRule {
  constructor() {
    super('SL-001', 'HIGH', 'Security Lake subscriber has overly broad permissions', ['aws_securitylake_subscriber']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_securitylake_subscriber') {
      const sources = resource.values?.source;
      if (Array.isArray(sources) && sources.length > 10) {
        return this.createScanResult(resource, projectName, this.description, 'Reduce source array to maximum 10 sources to follow least privilege.');
      }

      const subscriberIdentity = resource.values?.subscriber_identity;
      if (subscriberIdentity?.principal && typeof subscriberIdentity.principal === 'string' &&
          subscriberIdentity.principal.includes('*')) {
        return this.createScanResult(resource, projectName, this.description, 'Replace wildcard principal with a specific account ID or service domain.');
      }
    }

    return null;
  }
}

export default new TfSl001Rule();
