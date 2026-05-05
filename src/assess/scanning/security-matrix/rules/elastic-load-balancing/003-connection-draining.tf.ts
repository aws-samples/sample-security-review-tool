import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfElb003Rule extends BaseTerraformRule {
  constructor() {
    super('ELB-003', 'HIGH', 'Classic Load Balancer does not have connection draining enabled', ['aws_elb']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_elb') {
      const connectionDraining = resource.values?.connection_draining;
      if (connectionDraining !== true) {
        return this.createScanResult(resource, projectName, this.description, 'Set connection_draining = true and connection_draining_timeout = 300.');
      }
    }

    return null;
  }
}

export default new TfElb003Rule();
