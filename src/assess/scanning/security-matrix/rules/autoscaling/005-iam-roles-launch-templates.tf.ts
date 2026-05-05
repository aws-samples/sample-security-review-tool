import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfAutoscaling001Rule extends BaseTerraformRule {
  constructor() {
    super('AUTOSCALING-001', 'HIGH', 'Auto Scaling Group does not use launch template with IAM role configuration', ['aws_autoscaling_group']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_autoscaling_group') {
      const launchTemplate = resource.values?.launch_template;
      const mixedInstancesPolicy = resource.values?.mixed_instances_policy;

      if (!launchTemplate && !mixedInstancesPolicy) {
        return this.createScanResult(resource, projectName, this.description, 'Add launch_template block referencing an aws_launch_template with IAM instance profile.');
      }
    }

    return null;
  }
}

export default new TfAutoscaling001Rule();
