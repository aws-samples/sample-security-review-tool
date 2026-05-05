import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEc2009Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EC2-009',
      'MEDIUM',
      'EC2 instance outside of an Auto Scaling Group does not have termination protection enabled',
      ['aws_instance']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_instance') return null;

    if (resource.values?.disable_api_termination === true) {
      return null;
    }

    if (this.isPartOfAsg(resource, allResources)) {
      return null;
    }

    return this.createScanResult(
      resource,
      projectName,
      this.description,
      'Set disable_api_termination = true for the EC2 instance to enable termination protection.'
    );
  }

  private isPartOfAsg(instance: TerraformResource, allResources: TerraformResource[]): boolean {
    const hasAsg = allResources.some(r => r.type === 'aws_autoscaling_group');
    if (!hasAsg) return false;

    const instanceName = instance.name?.toLowerCase() || '';
    if (instanceName.includes('asg') || instanceName.includes('autoscaling')) {
      return true;
    }

    return false;
  }
}

export default new TfEc2009Rule();
