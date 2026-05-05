import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfFsxN001Rule extends BaseTerraformRule {
  constructor() {
    super(
      'FSx-N001',
      'HIGH',
      'FSx ONTAP security groups do not restrict access appropriately',
      ['aws_fsx_ontap_file_system']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const securityGroupIds = resource.values?.security_group_ids;

    if (!securityGroupIds || !Array.isArray(securityGroupIds) || securityGroupIds.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Specify security_group_ids with security groups that restrict access to the FSx ONTAP file system.`
      );
    }

    for (const sgId of securityGroupIds) {
      const sg = allResources.find(
        r => r.type === 'aws_security_group' && (r.values?.id === sgId || r.address === sgId)
      );

      if (sg && this.hasUnrestrictedIngress(sg, allResources)) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          `Security group ${sg.address} allows unrestricted access. Restrict ingress to specific CIDR blocks and required ports only.`
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

export default new TfFsxN001Rule();
