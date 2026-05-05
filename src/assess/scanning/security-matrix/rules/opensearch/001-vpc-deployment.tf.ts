import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEsh001Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ESH-001',
      'HIGH',
      'OpenSearch domain not deployed in VPC',
      ['aws_opensearch_domain']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const vpcOptions = resource.values?.vpc_options;

    if (!vpcOptions || !vpcOptions.subnet_ids || vpcOptions.subnet_ids.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Add vpc_options with subnet_ids to deploy domain in VPC.`
      );
    }

    return null;
  }
}

export default new TfEsh001Rule();
