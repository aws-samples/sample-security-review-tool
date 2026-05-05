import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfDms002Rule extends BaseTerraformRule {
  constructor() {
    super(
      'DMS-002',
      'HIGH',
      'DMS security group violates least privilege principles',
      ['aws_dms_replication_instance']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const vpcSecurityGroupIds = resource.values?.vpc_security_group_ids;

    if (!vpcSecurityGroupIds || !Array.isArray(vpcSecurityGroupIds)) {
      return null;
    }

    for (const sgId of vpcSecurityGroupIds) {
      const sg = allResources.find(
        r => r.type === 'aws_security_group' && (r.values?.id === sgId || r.address === sgId)
      );

      if (sg && this.hasOverlyPermissiveRules(sg, allResources)) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          `Restrict security group rules to specific ports, protocols, and CIDR blocks required for DMS operations.`
        );
      }
    }

    return null;
  }

  private hasOverlyPermissiveRules(sg: TerraformResource, allResources: TerraformResource[]): boolean {
    const ingress = sg.values?.ingress;
    if (Array.isArray(ingress)) {
      for (const rule of ingress) {
        if (this.isOverlyPermissive(rule)) {
          return true;
        }
      }
    }

    const egress = sg.values?.egress;
    if (Array.isArray(egress)) {
      for (const rule of egress) {
        if (this.isOverlyPermissive(rule)) {
          return true;
        }
      }
    }

    const sgRules = allResources.filter(
      r => r.type === 'aws_security_group_rule' &&
        r.values?.security_group_id === sg.values?.id
    );

    for (const rule of sgRules) {
      if (this.isOverlyPermissiveRule(rule)) {
        return true;
      }
    }

    return false;
  }

  private isOverlyPermissive(rule: any): boolean {
    const cidrBlocks = rule.cidr_blocks || [];
    const ipv6CidrBlocks = rule.ipv6_cidr_blocks || [];
    const protocol = rule.protocol;
    const fromPort = rule.from_port;
    const toPort = rule.to_port;

    if (protocol === '-1' || protocol === 'all') {
      return true;
    }

    if (fromPort === 0 && toPort === 65535) {
      return true;
    }

    if (cidrBlocks.includes('0.0.0.0/0') || ipv6CidrBlocks.includes('::/0')) {
      return true;
    }

    return false;
  }

  private isOverlyPermissiveRule(rule: TerraformResource): boolean {
    const cidrBlocks = rule.values?.cidr_blocks || [];
    const ipv6CidrBlocks = rule.values?.ipv6_cidr_blocks || [];
    const protocol = rule.values?.protocol;
    const fromPort = rule.values?.from_port;
    const toPort = rule.values?.to_port;

    if (protocol === '-1' || protocol === 'all') {
      return true;
    }

    if (fromPort === 0 && toPort === 65535) {
      return true;
    }

    if (cidrBlocks.includes('0.0.0.0/0') || ipv6CidrBlocks.includes('::/0')) {
      return true;
    }

    return false;
  }
}

export default new TfDms002Rule();
