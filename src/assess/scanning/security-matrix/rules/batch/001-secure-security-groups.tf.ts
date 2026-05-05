import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfBatch001Rule extends BaseTerraformRule {
  constructor() {
    super('BATCH-001', 'HIGH', 'Batch compute environment uses overly permissive security groups', ['aws_batch_compute_environment']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_batch_compute_environment') {
      const securityGroupIds = resource.values?.compute_resources?.security_group_ids;

      if (!securityGroupIds || !Array.isArray(securityGroupIds) || securityGroupIds.length === 0) {
        return this.createScanResult(resource, projectName, this.description, 'Add security_group_ids to compute_resources with restricted security groups.');
      }

      for (const sgId of securityGroupIds) {
        const sg = allResources.find(r =>
          r.type === 'aws_security_group' && r.values?.id === sgId
        );

        if (sg) {
          const ingress = sg.values?.ingress;
          if (Array.isArray(ingress)) {
            const hasOverlyPermissive = ingress.some((rule: any) =>
              rule.cidr_blocks?.includes('0.0.0.0/0') || rule.ipv6_cidr_blocks?.includes('::/0')
            );

            if (hasOverlyPermissive) {
              return this.createScanResult(resource, projectName, this.description, 'Restrict security group ingress rules to specific IP ranges and ports.');
            }
          }
        }
      }
    }

    return null;
  }
}

export default new TfBatch001Rule();
