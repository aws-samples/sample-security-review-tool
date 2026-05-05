import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT005Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-005', 'HIGH', 'IoT policy allows insecure communication protocols', ['aws_iot_policy']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_policy') {
      const policy = resource.values?.policy;
      if (typeof policy === 'string' && policy.includes('iot:Connect')) {
        if (!policy.includes('tls') && !policy.includes('TLS') && !policy.includes('mqtt')) {
          return null; // IoT Core enforces TLS by default
        }
      }
    }

    return null;
  }
}

export default new TfIoT005Rule();
