import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEks015Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EKS-015',
      'HIGH',
      'EKS cluster applications may be running as root user',
      ['aws_eks_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_eks_cluster') return null;

    return this.createScanResult(
      resource,
      projectName,
      `${this.description} (general guidance)`,
      "Ensure all container definitions include 'runAsNonRoot: true' and specify a non-root user ID in the security context."
    );
  }
}

export default new TfEks015Rule();
