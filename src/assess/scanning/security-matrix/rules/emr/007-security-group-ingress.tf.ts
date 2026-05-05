import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEmr007Rule extends BaseTerraformRule {
  constructor() {
    super('EMR-007', 'HIGH', 'EMR cluster security group allows open ingress (0.0.0.0/0)', ['aws_emr_cluster']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_emr_cluster') {
      const securityGroupIds = [
        resource.values?.ec2_attributes?.emr_managed_master_security_group,
        resource.values?.ec2_attributes?.emr_managed_slave_security_group,
        resource.values?.ec2_attributes?.[0]?.emr_managed_master_security_group,
        resource.values?.ec2_attributes?.[0]?.emr_managed_slave_security_group,
      ].filter(Boolean);

      for (const sgId of securityGroupIds) {
        const sg = allResources.find(r =>
          r.type === 'aws_security_group' && r.values?.id === sgId
        );

        if (sg) {
          const ingress = sg.values?.ingress;
          if (Array.isArray(ingress)) {
            const hasOpenIngress = ingress.some((rule: any) =>
              rule.cidr_blocks?.includes('0.0.0.0/0') || rule.ipv6_cidr_blocks?.includes('::/0')
            );

            if (hasOpenIngress) {
              return this.createScanResult(resource, projectName, this.description, 'Remove open ingress rules (0.0.0.0/0) from EMR security groups and restrict access to specific IP ranges.');
            }
          }
        }
      }
    }

    return null;
  }
}

export default new TfEmr007Rule();
