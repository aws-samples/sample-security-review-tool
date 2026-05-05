import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT001Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-001', 'HIGH', 'IoT resources lack proper visibility management or alerting mechanisms', ['aws_iot_thing', 'aws_iot_thing_group']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_thing') {
      const hasThingGroup = allResources.some(r =>
        r.type === 'aws_iot_thing_group_membership' ||
        r.type === 'aws_iot_thing_group'
      );

      if (!hasThingGroup) {
        return this.createScanResult(resource, projectName, this.description, 'Register IoT things in thing groups using aws_iot_thing_group for proper fleet management and visibility.');
      }
    }

    return null;
  }
}

export default new TfIoT001Rule();
