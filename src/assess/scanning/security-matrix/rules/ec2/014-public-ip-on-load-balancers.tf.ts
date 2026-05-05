import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEc2014Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EC2-014',
      'MEDIUM',
      'EC2 instance has a public IP address directly associated with it',
      ['aws_instance']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_instance') return null;

    if (resource.values?.associate_public_ip_address === true) {
      if (this.isBastionHost(resource)) {
        return null;
      }

      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Set associate_public_ip_address = false. Use a load balancer to expose services to the internet instead of directly exposing instances.'
      );
    }

    return null;
  }

  private isBastionHost(instance: TerraformResource): boolean {
    const name = instance.name?.toLowerCase() || '';
    const tags = instance.values?.tags || {};

    const nameTag = (tags.Name || '').toLowerCase();
    const combined = `${name} ${nameTag}`;

    const bastionIndicators = ['bastion', 'jump', 'ssh', 'rdp', 'gateway'];
    return bastionIndicators.some(indicator => combined.includes(indicator));
  }
}

export default new TfEc2014Rule();
