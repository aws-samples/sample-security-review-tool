import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT002Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-002', 'HIGH', 'IoT deployment lacks software integrity verification mechanisms', ['aws_iot_topic_rule']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_topic_rule') {
      const hasOtaUpdate = allResources.some(r =>
        r.type === 'aws_iot_ota_update'
      );

      const hasJobForUpdate = allResources.some(r =>
        r.type === 'aws_iot_job' ||
        (r.type === 'aws_iot_topic_rule' && JSON.stringify(r.values).includes('jobs'))
      );

      if (!hasOtaUpdate && !hasJobForUpdate) {
        return this.createScanResult(resource, projectName, this.description, 'Implement OTA updates using aws_iot_ota_update or IoT Jobs for software integrity verification.');
      }
    }

    return null;
  }
}

export default new TfIoT002Rule();
