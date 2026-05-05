import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfAs004Rule extends BaseTerraformRule {
  constructor() {
    super('AS-004', 'HIGH', 'Auto Scaling Group is not integrated with any load balancer', ['aws_autoscaling_group']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_autoscaling_group') {
      const targetGroupArns = resource.values?.target_group_arns;
      const loadBalancers = resource.values?.load_balancers;

      if ((!targetGroupArns || targetGroupArns.length === 0) &&
          (!loadBalancers || loadBalancers.length === 0)) {
        return this.createScanResult(resource, projectName, this.description, 'Set target_group_arns to integrate with an Application or Network Load Balancer.');
      }
    }

    return null;
  }
}

export default new TfAs004Rule();
