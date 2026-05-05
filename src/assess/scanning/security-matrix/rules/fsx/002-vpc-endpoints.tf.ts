import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfFsx002Rule extends BaseTerraformRule {
  constructor() {
    super(
      'FSx-002',
      'HIGH',
      'FSx file system does not use VPC endpoints for secure connectivity',
      ['aws_fsx_windows_file_system', 'aws_fsx_lustre_file_system', 'aws_fsx_ontap_file_system', 'aws_fsx_openzfs_file_system']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const subnetIds = resource.values?.subnet_ids || resource.values?.subnet_id;

    if (!subnetIds) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Create VPC endpoints for FSx service to ensure traffic stays within the AWS network.`
      );
    }

    const vpcEndpoints = allResources.filter(r => r.type === 'aws_vpc_endpoint');

    const hasFsxEndpoint = vpcEndpoints.some(endpoint => {
      const serviceName = endpoint.values?.service_name;
      return typeof serviceName === 'string' && serviceName.includes('fsx');
    });

    if (!hasFsxEndpoint) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Create VPC endpoints for FSx service to ensure traffic stays within the AWS network.`
      );
    }

    return null;
  }
}

export default new TfFsx002Rule();
