import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT023Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-023', 'HIGH', 'IoT deployment lacks proper certificate management', ['aws_iot_certificate']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_certificate') {
      if (resource.values?.active !== true) {
        return this.createScanResult(resource, projectName, this.description, 'Set active = true and ensure proper certificate lifecycle management.');
      }

      const hasAttachment = allResources.some(r =>
        r.type === 'aws_iot_thing_principal_attachment'
      );

      if (!hasAttachment) {
        return this.createScanResult(resource, projectName, this.description, 'Attach the certificate to an IoT thing using aws_iot_thing_principal_attachment.');
      }
    }

    return null;
  }
}

export default new TfIoT023Rule();
