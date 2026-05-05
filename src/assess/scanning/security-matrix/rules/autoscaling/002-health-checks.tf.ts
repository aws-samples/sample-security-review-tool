import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfAs002Rule extends BaseTerraformRule {
  constructor() {
    super('AS-002', 'HIGH', 'Auto Scaling Group does not have health check configuration', ['aws_autoscaling_group']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_autoscaling_group') {
      const healthCheckType = resource.values?.health_check_type;
      if (!healthCheckType || healthCheckType === 'EC2') {
        return this.createScanResult(resource, projectName, this.description, 'Set health_check_type = "ELB" and health_check_grace_period = 300 for comprehensive health monitoring.');
      }

      if (healthCheckType === 'ELB' && !resource.values?.health_check_grace_period) {
        return this.createScanResult(resource, projectName, this.description, 'Set health_check_grace_period = 300 to allow instances time to initialize.');
      }
    }

    return null;
  }
}

export default new TfAs002Rule();
