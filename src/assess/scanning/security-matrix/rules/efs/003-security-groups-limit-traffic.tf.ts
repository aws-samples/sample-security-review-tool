import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEfs003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EFS-003',
      'HIGH',
      'EFS security groups allow traffic from overly permissive IP ranges',
      ['aws_efs_mount_target']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const securityGroups = resource.values?.security_groups;

    if (!securityGroups || !Array.isArray(securityGroups) || securityGroups.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Specify security_groups for the EFS mount target that restrict access to specific IP ranges.`
      );
    }

    for (const sgId of securityGroups) {
      const sg = allResources.find(
        r => r.type === 'aws_security_group' && (r.values?.id === sgId || r.address === sgId)
      );

      if (sg && this.hasOverlyPermissiveNfsAccess(sg, allResources)) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          `Security group ${sg.address} allows overly permissive access on NFS port 2049. Restrict to specific IP ranges.`
        );
      }
    }

    return null;
  }

  private hasOverlyPermissiveNfsAccess(sg: TerraformResource, allResources: TerraformResource[]): boolean {
    const ingress = sg.values?.ingress;
    if (Array.isArray(ingress)) {
      for (const rule of ingress) {
        if (this.isNfsPortRange(rule.from_port, rule.to_port)) {
          const cidrBlocks = rule.cidr_blocks || [];
          const ipv6CidrBlocks = rule.ipv6_cidr_blocks || [];
          if (cidrBlocks.includes('0.0.0.0/0') || ipv6CidrBlocks.includes('::/0')) {
            return true;
          }
          if (this.hasWideCidr(cidrBlocks)) {
            return true;
          }
        }
      }
    }

    const ingressRules = allResources.filter(
      r => r.type === 'aws_security_group_rule' &&
        r.values?.type === 'ingress' &&
        r.values?.security_group_id === sg.values?.id
    );

    for (const rule of ingressRules) {
      if (this.isNfsPortRange(rule.values?.from_port, rule.values?.to_port)) {
        const cidrBlocks = rule.values?.cidr_blocks || [];
        const ipv6CidrBlocks = rule.values?.ipv6_cidr_blocks || [];
        if (cidrBlocks.includes('0.0.0.0/0') || ipv6CidrBlocks.includes('::/0')) {
          return true;
        }
        if (this.hasWideCidr(cidrBlocks)) {
          return true;
        }
      }
    }

    return false;
  }

  private isNfsPortRange(fromPort: number | undefined, toPort: number | undefined): boolean {
    if (fromPort === undefined || toPort === undefined) return false;
    return fromPort <= 2049 && toPort >= 2049;
  }

  private hasWideCidr(cidrBlocks: string[]): boolean {
    for (const cidr of cidrBlocks) {
      if (typeof cidr === 'string') {
        const parts = cidr.split('/');
        if (parts.length === 2) {
          const prefix = parseInt(parts[1], 10);
          if (!isNaN(prefix) && prefix < 16) {
            return true;
          }
        }
      }
    }
    return false;
  }
}

export default new TfEfs003Rule();
