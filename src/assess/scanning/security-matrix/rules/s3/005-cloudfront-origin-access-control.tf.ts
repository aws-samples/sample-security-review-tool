import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfS3005Rule extends BaseTerraformRule {
  constructor() {
    super(
      'S3-005',
      'HIGH',
      'S3 bucket used as CloudFront origin lacks access restriction (OAC or OAI)',
      ['aws_s3_bucket']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_s3_bucket') return null;

    if (!this.isCloudFrontOrigin(resource, allResources)) return null;

    if (this.hasAccessRestriction(resource, allResources)) return null;

    return this.createScanResult(
      resource,
      projectName,
      this.description,
      'Configure Origin Access Control (OAC) or Origin Access Identity (OAI) for CloudFront distributions using this bucket, and update bucket policy to restrict access.'
    );
  }

  private isCloudFrontOrigin(bucket: TerraformResource, allResources: TerraformResource[]): boolean {
    return allResources.some(r => {
      if (r.type !== 'aws_cloudfront_distribution') return false;

      const origins = r.values?.origin;
      if (!Array.isArray(origins)) return false;

      return origins.some((origin: any) =>
        origin.domain_name && this.originReferencesBucket(origin, bucket)
      );
    });
  }

  private originReferencesBucket(origin: any, bucket: TerraformResource): boolean {
    const domainName = origin.domain_name;
    if (typeof domainName !== 'string') return false;

    const bucketName = bucket.values?.bucket;
    if (bucketName && domainName.includes(bucketName)) return true;

    const bucketRegionalDomain = bucket.values?.bucket_regional_domain_name;
    if (bucketRegionalDomain && domainName === bucketRegionalDomain) return true;

    return false;
  }

  private hasAccessRestriction(bucket: TerraformResource, allResources: TerraformResource[]): boolean {
    const distributions = allResources.filter(r => r.type === 'aws_cloudfront_distribution');

    for (const dist of distributions) {
      const origins = dist.values?.origin;
      if (!Array.isArray(origins)) continue;

      for (const origin of origins) {
        if (!this.originReferencesBucket(origin, bucket)) continue;

        if (origin.origin_access_control_id) return true;

        if (origin.s3_origin_config?.origin_access_identity) return true;
      }
    }

    return false;
  }
}

export default new TfS3005Rule();
