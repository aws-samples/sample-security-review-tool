import { BaseRule, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * ATH2 Rule: Is encryption in transit being used for communication to the S3 bucket?
 * 
 * Documentation: "Solutions must ensure that only encrypted connections over HTTPS (TLS) 
 * are allowed using the aws:SecureTransport condition on Amazon S3 bucket IAM policies."
 */
export class ATH002Rule extends BaseRule {
  constructor() {
    super(
      'ATH-002',
      'HIGH',
      'Athena WorkGroup uses S3 bucket without HTTPS/TLS enforcement (aws:SecureTransport)',
      ['AWS::Athena::WorkGroup']
    );
  }

  public evaluate(): ScanResult | null {
    return null;
  }

  public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
    if (resource.Type !== 'AWS::Athena::WorkGroup')  return null;

    // ATH2: Is encryption in transit being used for communication to the S3 bucket?
    const outputLocation = resource.Properties?.WorkGroupConfiguration?.ResultConfiguration?.OutputLocation;

    // If outputLocation exists but isn't a string, it means intrinsic function couldn't be resolved
    if (!outputLocation || typeof outputLocation !== 'string' || !outputLocation.startsWith('s3://')) {
      return this.createResult(
        stackName,
        template,
        resource,
        `${this.description}`,
        `Unable to validate OutputLocation because it either doesn't exist, isn't a valid S3 URL, or is an unresolved intrinsic function.`
      );
    }

    // Extract bucket name from s3://bucket-name/path
    const bucketName = outputLocation.substring(5).split('/')[0];

    // Find bucket policy for this S3 bucket
    const bucketPolicy = Object.values(template.Resources || []).find(r =>
      r.Type === 'AWS::S3::BucketPolicy' &&
      (r.Properties?.Bucket === bucketName || r.Properties?.Bucket?.Ref === bucketName)
    );

    if (!bucketPolicy || !this.hasSecureTransportPolicy(bucketPolicy)) {
      return this.createResult(
        stackName,
        template,
        resource,
        `${this.description}`,
        `Add S3 bucket policy for '${bucketName}' with Deny statement: Condition: Bool: 'aws:SecureTransport': 'false'.`
      );
    }

    // HTTPS enforcement is enabled for Athena S3 bucket - ATH2 requirement satisfied
    return null;
  }

  private hasSecureTransportPolicy(bucketPolicyResource: Resource): boolean {
    const policyDocument = bucketPolicyResource.Properties?.PolicyDocument;
    
    if (!policyDocument?.Statement || !Array.isArray(policyDocument.Statement)) {
      return false;
    }

    // Look for a Deny statement with aws:SecureTransport condition
    return policyDocument.Statement.some((statement: any) => 
      statement.Effect === 'Deny' &&
      statement.Condition?.Bool?.['aws:SecureTransport'] === 'false'
    );
  }
}

export default new ATH002Rule();
