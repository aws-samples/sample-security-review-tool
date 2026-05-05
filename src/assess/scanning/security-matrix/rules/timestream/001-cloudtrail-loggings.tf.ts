import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfTimestream001Rule extends BaseTerraformRule {
  constructor() {
    super(
      'TIMESTREAM-001',
      'HIGH',
      'Timestream resources deployed without CloudTrail logging configured',
      ['aws_timestreamwrite_database']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const cloudTrails = allResources.filter(r => r.type === 'aws_cloudtrail');

    if (cloudTrails.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Create an aws_cloudtrail resource to log Timestream API calls, or ensure CloudTrail is configured externally for this account.`
      );
    }

    const hasValidTrail = cloudTrails.some(trail => this.isValidCloudTrail(trail));

    if (!hasValidTrail) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Ensure CloudTrail has enable_logging = true and an s3_bucket_name configured to capture Timestream API calls.`
      );
    }

    return null;
  }

  private isValidCloudTrail(trail: TerraformResource): boolean {
    const enableLogging = trail.values?.enable_logging;
    if (enableLogging === false) {
      return false;
    }

    const s3BucketName = trail.values?.s3_bucket_name;
    if (!s3BucketName) {
      return false;
    }

    return true;
  }
}

export default new TfTimestream001Rule();
