import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfAth002Rule extends BaseTerraformRule {
  constructor() {
    super('ATH-002', 'HIGH', 'Athena WorkGroup uses S3 bucket without HTTPS/TLS enforcement (aws:SecureTransport)', ['aws_athena_workgroup']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_athena_workgroup') {
      const outputLocation = resource.values?.configuration?.result_configuration?.output_location;

      if (!outputLocation || typeof outputLocation !== 'string' || !outputLocation.startsWith('s3://')) {
        return this.createScanResult(resource, projectName, this.description, 'Configure output_location with a valid S3 URL and ensure the bucket has a policy enforcing aws:SecureTransport.');
      }

      const bucketName = outputLocation.substring(5).split('/')[0];
      const bucketPolicies = allResources.filter(r =>
        r.type === 'aws_s3_bucket_policy' &&
        r.values?.bucket === bucketName
      );

      const hasSecureTransport = bucketPolicies.some(bp => {
        const policy = bp.values?.policy;
        if (typeof policy === 'string') {
          return policy.includes('aws:SecureTransport') && policy.includes('Deny');
        }
        return false;
      });

      if (!hasSecureTransport) {
        return this.createScanResult(resource, projectName, this.description, 'Add S3 bucket policy for "' + bucketName + '" with Deny statement when aws:SecureTransport is false.');
      }
    }

    return null;
  }
}

export default new TfAth002Rule();
