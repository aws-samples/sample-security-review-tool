import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT030Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-030', 'HIGH', 'IoT deployment lacks Device Defender continuous monitoring', ['aws_iot_topic_rule']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_topic_rule') {
      const hasSecurityProfile = allResources.some(r =>
        r.type === 'aws_iot_security_profile'
      );

      if (!hasSecurityProfile) {
        return this.createScanResult(resource, projectName, this.description, 'Add aws_iot_security_profile for Device Defender Detect to continuously monitor device behavior.');
      }
    }

    return null;
  }
}

export default new TfIoT030Rule();
