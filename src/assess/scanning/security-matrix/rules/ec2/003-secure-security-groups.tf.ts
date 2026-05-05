import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEc2003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EC2-003',
      'HIGH',
      'Security group allows unrestricted inbound access from 0.0.0.0/0',
      ['aws_security_group', 'aws_security_group_rule']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_security_group') {
      const ingress = resource.values?.ingress;
      if (ingress && Array.isArray(ingress)) {
        for (const rule of ingress) {
          if (this.isOpenToWorld(rule)) {
            return this.createScanResult(
              resource,
              projectName,
              this.description,
              'Restrict ingress rules to specific IP ranges instead of 0.0.0.0/0 or ::/0.'
            );
          }
        }
      }
    }

    if (resource.type === 'aws_security_group_rule') {
      if (resource.values?.type !== 'ingress') return null;

      if (this.isOpenToWorld(resource.values)) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Restrict ingress rules to specific IP ranges instead of 0.0.0.0/0 or ::/0.'
        );
      }
    }

    return null;
  }

  private isOpenToWorld(rule: any): boolean {
    const cidrBlocks = rule.cidr_blocks;
    const ipv6CidrBlocks = rule.ipv6_cidr_blocks;

    const hasPublicIpv4 = Array.isArray(cidrBlocks) && cidrBlocks.includes('0.0.0.0/0');
    const hasPublicIpv6 = Array.isArray(ipv6CidrBlocks) && ipv6CidrBlocks.includes('::/0');

    if (!hasPublicIpv4 && !hasPublicIpv6) return false;

    const fromPort = rule.from_port;
    if (fromPort === 22 || fromPort === 3389) {
      return false;
    }

    return true;
  }
}

export default new TfEc2003Rule();
