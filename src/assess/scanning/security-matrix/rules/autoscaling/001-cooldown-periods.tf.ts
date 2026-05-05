import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfAs001Rule extends BaseTerraformRule {
  constructor() {
    super('AS-001', 'HIGH', 'Auto Scaling Group does not have cooldown period configured', ['aws_autoscaling_group']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_autoscaling_group') {
      const defaultCooldown = resource.values?.default_cooldown;
      if (!defaultCooldown) {
        return this.createScanResult(resource, projectName, this.description, 'Set default_cooldown = 300 to allow newly launched instances time to start handling traffic.');
      }
    }

    return null;
  }
}

export default new TfAs001Rule();
