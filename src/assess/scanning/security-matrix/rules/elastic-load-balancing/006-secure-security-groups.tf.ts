import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfElb006Rule extends BaseTerraformRule {
  constructor() {
    super('ELB-006', 'HIGH', 'Load balancer security groups allow overly permissive access', ['aws_lb', 'aws_elb']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const securityGroups = resource.values?.security_groups;
    if (!securityGroups || !Array.isArray(securityGroups) || securityGroups.length === 0) {
      return this.createScanResult(resource, projectName, this.description, 'Associate the load balancer with security groups that restrict access to listener ports only.');
    }

    for (const sgId of securityGroups) {
      const sg = allResources.find(r =>
        r.type === 'aws_security_group' && r.values?.id === sgId
      );

      if (sg) {
        const ingress = sg.values?.ingress;
        if (Array.isArray(ingress)) {
          for (const rule of ingress) {
            const cidrBlocks = rule.cidr_blocks || [];
            if (cidrBlocks.includes('0.0.0.0/0') && rule.from_port === 0 && rule.to_port === 65535) {
              return this.createScanResult(resource, projectName, this.description, 'Restrict security group ingress rules to only allow necessary ports and limit source IP ranges.');
            }
          }
        }
      }
    }

    return null;
  }
}

export default new TfElb006Rule();
