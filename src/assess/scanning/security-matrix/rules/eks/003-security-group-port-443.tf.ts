import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEks003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EKS-003',
      'HIGH',
      'EKS cluster security group allows inbound traffic on ports other than 443',
      ['aws_eks_cluster', 'aws_security_group']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_security_group') {
      if (!this.isEksSecurityGroup(resource, allResources)) return null;
      return this.evaluateSecurityGroup(resource, projectName);
    }

    if (resource.type === 'aws_eks_cluster') {
      const vpcConfig = resource.values?.vpc_config;
      if (!vpcConfig || !Array.isArray(vpcConfig) || vpcConfig.length === 0) return null;

      const securityGroupIds = vpcConfig[0].security_group_ids;
      if (!securityGroupIds || !Array.isArray(securityGroupIds)) return null;

      for (const sgId of securityGroupIds) {
        const sg = allResources.find(r => r.type === 'aws_security_group' && r.address === sgId);
        if (sg) {
          const result = this.evaluateSecurityGroup(sg, projectName);
          if (result) return result;
        }
      }
    }

    return null;
  }

  private evaluateSecurityGroup(sg: TerraformResource, projectName: string): ScanResult | null {
    const ingress = sg.values?.ingress;
    if (!ingress || !Array.isArray(ingress)) return null;

    for (const rule of ingress) {
      const protocol = rule.protocol;
      if (protocol !== 'tcp' && protocol !== '6') continue;

      const fromPort = rule.from_port;
      const toPort = rule.to_port;

      if (fromPort !== 443 || toPort !== 443) {
        return this.createScanResult(
          sg,
          projectName,
          `${this.description} (allows traffic on port range ${fromPort}-${toPort})`,
          'Restrict inbound traffic to only TCP port 443 for HTTPS.'
        );
      }
    }

    return null;
  }

  private isEksSecurityGroup(sg: TerraformResource, allResources: TerraformResource[]): boolean {
    return allResources.some(r => {
      if (r.type !== 'aws_eks_cluster') return false;
      const vpcConfig = r.values?.vpc_config;
      if (!vpcConfig || !Array.isArray(vpcConfig) || vpcConfig.length === 0) return false;
      const sgIds = vpcConfig[0].security_group_ids;
      return Array.isArray(sgIds) && sgIds.includes(sg.address);
    });
  }
}

export default new TfEks003Rule();
