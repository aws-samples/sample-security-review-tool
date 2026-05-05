import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT033Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-033', 'MEDIUM', 'IoT deployment does not use VPC PrivateLink for internal service communication', ['aws_iot_topic_rule']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_topic_rule') {
      const hasVpcEndpoint = allResources.some(r =>
        r.type === 'aws_vpc_endpoint' &&
        (r.values?.service_name?.includes('iot') || r.values?.service_name?.includes('execute-api'))
      );

      if (!hasVpcEndpoint) {
        return this.createScanResult(resource, projectName, this.description, 'Add aws_vpc_endpoint for IoT services to use VPC PrivateLink for internal communication.');
      }
    }

    return null;
  }
}

export default new TfIoT033Rule();
