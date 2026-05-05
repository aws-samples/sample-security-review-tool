import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEcr001Rule extends BaseTerraformRule {
  constructor() {
    super('ECR-001', 'HIGH', 'ECR repository is configured as public which may expose proprietary code', ['aws_ecrpublic_repository', 'aws_ecr_repository']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_ecrpublic_repository') {
      return this.createScanResult(resource, projectName, this.description, 'Use aws_ecr_repository (private) instead unless public access is intentional and documented.');
    }

    if (resource.type === 'aws_ecr_repository') {
      const policy = allResources.find(r =>
        r.type === 'aws_ecr_repository_policy' &&
        r.values?.repository === resource.values?.name
      );

      if (policy) {
        const policyText = policy.values?.policy || '';
        const policyStr = typeof policyText === 'string' ? policyText : JSON.stringify(policyText);

        if (policyStr.includes('"Principal":"*"') || policyStr.includes('"AWS":"*"')) {
          return this.createScanResult(resource, projectName, this.description + ' through overly permissive repository policy', 'Restrict the repository policy to specific principals or add appropriate conditions.');
        }
      }
    }

    return null;
  }
}

export default new TfEcr001Rule();
