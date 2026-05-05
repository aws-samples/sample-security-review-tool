import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEsh003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ESH-003',
      'HIGH',
      'OpenSearch security group allows unrestricted access',
      ['aws_opensearch_domain']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const vpcOptions = resource.values?.vpc_options;

    if (!vpcOptions || !vpcOptions.security_group_ids || vpcOptions.security_group_ids.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Add security_group_ids to vpc_options with restricted access rules.`
      );
    }

    const securityGroupIds: string[] = vpcOptions.security_group_ids;

    for (const sgId of securityGroupIds) {
      const sg = allResources.find(
        r => r.type === 'aws_security_group' && (r.values?.id === sgId || r.address === sgId)
      );

      if (sg && this.hasPermissiveIngress(sg, allResources)) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          `Security group ${sg.address} has overly permissive ingress rules. Limit access to specific IP ranges or security groups.`
        );
      }
    }

    return null;
  }

  private hasPermissiveIngress(sg: TerraformResource, allResources: TerraformResource[]): boolean {
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

export default new TfEsh003Rule();
