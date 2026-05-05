import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEmr001Rule extends BaseTerraformRule {
  constructor() {
    super('EMR-001', 'HIGH', 'EMR cluster is not configured with VPC private subnet', ['aws_emr_cluster']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_emr_cluster') {
      const subnetId = resource.values?.ec2_attributes?.subnet_id
        || resource.values?.ec2_attributes?.[0]?.subnet_id;

      if (!subnetId) {
        return this.createScanResult(resource, projectName, this.description, 'Set ec2_attributes.subnet_id to place the EMR cluster in a VPC private subnet.');
      }
    }

    return null;
  }
}

export default new TfEmr001Rule();
