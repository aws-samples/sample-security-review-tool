import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEc2005Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EC2-005',
      'MEDIUM',
      'Security group allows unrestricted outbound access to the entire Internet',
      ['aws_security_group', 'aws_security_group_rule']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_security_group') {
      const egress = resource.values?.egress;

      if (!egress || (Array.isArray(egress) && egress.length === 0)) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Add explicit egress rules to the security group that restrict outbound traffic to specific IP ranges and ports required by the application.'
        );
      }

      if (Array.isArray(egress)) {
        for (const rule of egress) {
          if (this.isOverlyPermissiveEgress(rule)) {
            return this.createScanResult(
              resource,
              projectName,
              this.description,
              'Restrict egress rules to specific IP ranges and ports required by the application instead of allowing all traffic to 0.0.0.0/0 or ::/0.'
            );
          }
        }
      }
    }

    if (resource.type === 'aws_security_group_rule') {
      if (resource.values?.type !== 'egress') return null;

      if (this.isOverlyPermissiveEgress(resource.values)) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Restrict egress rules to specific IP ranges and ports required by the application instead of allowing all traffic to 0.0.0.0/0 or ::/0.'
        );
      }
    }

    return null;
  }

  private isOverlyPermissiveEgress(rule: any): boolean {
    const cidrBlocks = rule.cidr_blocks;
    const ipv6CidrBlocks = rule.ipv6_cidr_blocks;

    const hasUnrestrictedIpv4 = Array.isArray(cidrBlocks) && cidrBlocks.includes('0.0.0.0/0');
    const hasUnrestrictedIpv6 = Array.isArray(ipv6CidrBlocks) && ipv6CidrBlocks.includes('::/0');

    if (!hasUnrestrictedIpv4 && !hasUnrestrictedIpv6) return false;

    const protocol = rule.protocol;
    const fromPort = rule.from_port;
    const toPort = rule.to_port;

    if (protocol === '-1' || protocol === 'all') return false;

    if (protocol === 'tcp' && fromPort === 80 && toPort === 80) return false;
    if (protocol === 'tcp' && fromPort === 443 && toPort === 443) return false;
    if (protocol === 'udp' && fromPort === 53 && toPort === 53) return false;
    if (protocol === 'tcp' && fromPort === 53 && toPort === 53) return false;

    return true;
  }
}

export default new TfEc2005Rule();
