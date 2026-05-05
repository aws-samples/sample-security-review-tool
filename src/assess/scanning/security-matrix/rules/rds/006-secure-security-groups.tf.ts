import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRds006Rule extends BaseTerraformRule {
  constructor() {
    super(
      'RDS-006',
      'HIGH',
      'RDS security group allows access from 0.0.0.0/0',
      ['aws_security_group', 'aws_security_group_rule']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_security_group') {
      if (!this.isRdsSecurityGroup(resource, allResources)) {
        return null;
      }

      const ingress = resource.values?.ingress;
      if (ingress && Array.isArray(ingress)) {
        for (const rule of ingress) {
          if (this.isPublicCidr(rule.cidr_blocks) || this.isPublicIpv6Cidr(rule.ipv6_cidr_blocks)) {
            const port = this.getPortDescription(rule.from_port, rule.to_port);
            return this.createScanResult(
              resource,
              projectName,
              `${this.description} on port ${port}`,
              'Restrict cidr_blocks to specific IP ranges that need access.'
            );
          }
        }
      }
    }

    if (resource.type === 'aws_security_group_rule') {
      if (resource.values?.type !== 'ingress') {
        return null;
      }

      const securityGroupId = resource.values?.security_group_id;
      if (!securityGroupId || !this.isRdsSecurityGroupById(securityGroupId, allResources)) {
        return null;
      }

      if (this.isPublicCidr(resource.values?.cidr_blocks) || this.isPublicIpv6Cidr(resource.values?.ipv6_cidr_blocks)) {
        const port = this.getPortDescription(resource.values?.from_port, resource.values?.to_port);
        return this.createScanResult(
          resource,
          projectName,
          `${this.description} on port ${port}`,
          'Restrict cidr_blocks to specific IP ranges that need access.'
        );
      }
    }

    return null;
  }

  private isRdsSecurityGroup(sg: TerraformResource, allResources: TerraformResource[]): boolean {
    const rdsResources = allResources.filter(r =>
      r.type === 'aws_db_instance' || r.type === 'aws_rds_cluster'
    );

    for (const rds of rdsResources) {
      const vpcSecurityGroupIds = rds.values?.vpc_security_group_ids;
      if (Array.isArray(vpcSecurityGroupIds) && vpcSecurityGroupIds.includes(sg.address)) {
        return true;
      }
    }

    const sgName = sg.values?.name;
    if (typeof sgName === 'string' && (sgName.toLowerCase().includes('rds') || sgName.toLowerCase().includes('database'))) {
      return true;
    }

    return false;
  }

  private isRdsSecurityGroupById(sgId: string, allResources: TerraformResource[]): boolean {
    const sg = allResources.find(r => r.type === 'aws_security_group' && r.address === sgId);
    if (sg) {
      return this.isRdsSecurityGroup(sg, allResources);
    }
    return false;
  }

  private isPublicCidr(cidrBlocks: any): boolean {
    if (!Array.isArray(cidrBlocks)) return false;
    return cidrBlocks.includes('0.0.0.0/0');
  }

  private isPublicIpv6Cidr(cidrBlocks: any): boolean {
    if (!Array.isArray(cidrBlocks)) return false;
    return cidrBlocks.includes('::/0');
  }

  private getPortDescription(fromPort: any, toPort: any): string {
    if (fromPort === undefined || toPort === undefined) {
      return 'all ports';
    }
    if (fromPort === toPort) {
      return `${fromPort}`;
    }
    return `${fromPort}-${toPort}`;
  }
}

export default new TfRds006Rule();
