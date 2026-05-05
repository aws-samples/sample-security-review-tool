import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfAs003Rule extends BaseTerraformRule {
  constructor() {
    super('AS-003', 'HIGH', 'Auto Scaling Group does not have notification configurations', ['aws_autoscaling_group']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_autoscaling_group') {
      const hasNotification = allResources.some(r =>
        r.type === 'aws_autoscaling_notification' &&
        r.values?.group_names?.includes(resource.values?.name)
      );

      if (!hasNotification) {
        return this.createScanResult(resource, projectName, this.description, 'Add aws_autoscaling_notification resource with topic_arn and notifications for scaling events.');
      }
    }

    return null;
  }
}

export default new TfAs003Rule();
