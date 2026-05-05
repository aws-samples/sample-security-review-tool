import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfFsxN002Rule extends BaseTerraformRule {
  constructor() {
    super(
      'FSx-N002',
      'HIGH',
      'FSx ONTAP file system does not restrict SSH and API access',
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
        `Specify security_group_ids with security groups that restrict SSH (port 22) and API (port 443) access to authorized networks.`
      );
    }

    for (const sgId of securityGroupIds) {
      const sg = allResources.find(
        r => r.type === 'aws_security_group' && (r.values?.id === sgId || r.address === sgId)
      );

      if (sg && this.hasUnrestrictedSshOrApiAccess(sg, allResources)) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          `Security group ${sg.address} allows unrestricted SSH or API access. Restrict SSH (port 22) and API (port 443) to specific CIDR blocks.`
        );
      }
    }

    return null;
  }

  private hasUnrestrictedSshOrApiAccess(sg: TerraformResource, allResources: TerraformResource[]): boolean {
    const ingress = sg.values?.ingress;
    if (Array.isArray(ingress)) {
      for (const rule of ingress) {
        if (this.isSshOrApiPort(rule.from_port, rule.to_port)) {
          const cidrBlocks = rule.cidr_blocks || [];
          const ipv6CidrBlocks = rule.ipv6_cidr_blocks || [];
          if (cidrBlocks.includes('0.0.0.0/0') || ipv6CidrBlocks.includes('::/0')) {
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
      if (this.isSshOrApiPort(rule.values?.from_port, rule.values?.to_port)) {
        const cidrBlocks = rule.values?.cidr_blocks || [];
        const ipv6CidrBlocks = rule.values?.ipv6_cidr_blocks || [];
        if (cidrBlocks.includes('0.0.0.0/0') || ipv6CidrBlocks.includes('::/0')) {
          return true;
        }
      }
    }

    return false;
  }

  private isSshOrApiPort(fromPort: number | undefined, toPort: number | undefined): boolean {
    if (fromPort === undefined || toPort === undefined) return false;
    const sshPort = 22;
    const apiPort = 443;
    return (fromPort <= sshPort && toPort >= sshPort) ||
      (fromPort <= apiPort && toPort >= apiPort);
  }
}

export default new TfFsxN002Rule();
