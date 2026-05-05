import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfDocdb003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'DOCDB-003',
      'HIGH',
      'DocumentDB cluster security groups allow unrestricted ingress from 0.0.0.0/0',
      ['aws_docdb_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const vpcSecurityGroupIds = resource.values?.vpc_security_group_ids;

    if (!vpcSecurityGroupIds || !Array.isArray(vpcSecurityGroupIds) || vpcSecurityGroupIds.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Specify vpc_security_group_ids with security groups that restrict access and do not allow ingress from 0.0.0.0/0.`
      );
    }

    for (const sgId of vpcSecurityGroupIds) {
      const sg = allResources.find(
        r => r.type === 'aws_security_group' && (r.values?.id === sgId || r.address === sgId)
      );

      if (sg && this.hasUnrestrictedIngress(sg, allResources)) {
        return this.createScanResult(
          resource,
          projectName,
          `Security group ${sg.address} allows 0.0.0.0/0`,
          `Restrict ingress rules on security group ${sg.address} to specific CIDR blocks.`
        );
      }
    }

    return null;
  }

  private hasUnrestrictedIngress(sg: TerraformResource, allResources: TerraformResource[]): boolean {
    const ingress = sg.values?.ingress;
    if (Array.isArray(ingress)) {
      for (const rule of ingress) {
        const cidrBlocks = rule.cidr_blocks || [];
        const ipv6CidrBlocks = rule.ipv6_cidr_blocks || [];
        if (cidrBlocks.includes('0.0.0.0/0') || ipv6CidrBlocks.includes('::/0')) {
          return true;
        }
      }
    }

    const ingressRules = allResources.filter(
      r => r.type === 'aws_security_group_rule' &&
        r.values?.type === 'ingress' &&
        r.values?.security_group_id === sg.values?.id
    );

    for (const rule of ingressRules) {
      const cidrBlocks = rule.values?.cidr_blocks || [];
      const ipv6CidrBlocks = rule.values?.ipv6_cidr_blocks || [];
      if (cidrBlocks.includes('0.0.0.0/0') || ipv6CidrBlocks.includes('::/0')) {
        return true;
      }
    }

    return false;
  }
}

export default new TfDocdb003Rule();
