import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT011Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-011', 'HIGH', 'IoT devices lack unique identity configuration', ['aws_iot_thing']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_thing') {
      const hasCertificate = allResources.some(r =>
        r.type === 'aws_iot_certificate' ||
        r.type === 'aws_iot_thing_principal_attachment'
      );

      if (!hasCertificate) {
        return this.createScanResult(resource, projectName, this.description, 'Attach a unique certificate to each IoT thing using aws_iot_thing_principal_attachment.');
      }
    }

    return null;
  }
}

export default new TfIoT011Rule();
