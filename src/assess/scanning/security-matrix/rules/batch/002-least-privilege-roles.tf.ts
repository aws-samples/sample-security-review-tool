import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfBatch002Rule extends BaseTerraformRule {
  constructor() {
    super('BATCH-002', 'HIGH', 'Batch job definition uses overly permissive IAM roles', ['aws_batch_job_definition']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_batch_job_definition') {
      const containerProperties = resource.values?.container_properties;
      let parsed: any = containerProperties;

      if (typeof containerProperties === 'string') {
        try {
          parsed = JSON.parse(containerProperties);
        } catch {
          return null;
        }
      }

      if (!parsed?.jobRoleArn) {
        return this.createScanResult(resource, projectName, this.description, 'Add jobRoleArn to container_properties with a least-privilege IAM role.');
      }
    }

    return null;
  }
}

export default new TfBatch002Rule();
