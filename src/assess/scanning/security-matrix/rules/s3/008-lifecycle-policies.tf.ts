import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfS3008Rule extends BaseTerraformRule {
  constructor() {
    super(
      'S3-008',
      'HIGH',
      'S3 bucket lacks lifecycle policy',
      ['aws_s3_bucket']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_s3_bucket') return null;

    const hasLifecycleConfig = allResources.some(r =>
      r.type === 'aws_s3_bucket_lifecycle_configuration' &&
      (r.values?.bucket === resource.values?.bucket || r.values?.bucket === resource.values?.id)
    );

    if (hasLifecycleConfig) return null;

    return this.createScanResult(
      resource,
      projectName,
      this.description,
      'Configure an aws_s3_bucket_lifecycle_configuration resource to manage S3 objects during their lifetime.'
    );
  }
}

export default new TfS3008Rule();
