import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfElb002Rule extends BaseTerraformRule {
  constructor() {
    super('ELB-002', 'HIGH', 'Load balancer does not have access logs enabled', ['aws_lb', 'aws_elb']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_lb') {
      const accessLogs = resource.values?.access_logs;
      if (!accessLogs || accessLogs.enabled !== true) {
        return this.createScanResult(resource, projectName, this.description, 'Add access_logs block with enabled = true and bucket specified.');
      }
    }

    if (resource.type === 'aws_elb') {
      const accessLogs = resource.values?.access_logs;
      if (!accessLogs || accessLogs.enabled !== true) {
        return this.createScanResult(resource, projectName, this.description, 'Add access_logs block with enabled = true and bucket specified.');
      }
    }

    return null;
  }
}

export default new TfElb002Rule();
