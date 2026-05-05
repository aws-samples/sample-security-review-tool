import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * CFR006 Rule: Use origin access control (OAC) to control access between S3 and CloudFront.
 * 
 * Documentation: "Ensure that the origin access control feature is enabled for all solution distributions that utilize an S3 bucket as an origin in order to restrict any direct access to objects through Amazon S3 URLs."
 * 
 * Note: Basic Origin Access Identity check is covered by Checkov rule CKV_AWS_120, which checks if CloudFront distribution uses Origin Access Identity for S3 origins.
 * This rule adds value by checking for both OAI (legacy) and OAC (recommended) configurations, and by recommending the newer OAC approach.
 * It also checks for alternative security mechanisms like bucket policies that grant access to CloudFront.
 */
export class CFR006Rule extends BaseRule {
  constructor() {
    super(
      'CFR-006',
      'HIGH',
      'CloudFront S3 origin lacks Origin Access Control',
      ['AWS::CloudFront::Distribution']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type === 'AWS::CloudFront::Distribution') {
      const distributionConfig = resource.Properties?.DistributionConfig;

      if (!distributionConfig) {
        return null;
      }

      // Check origins for S3 origins
      const origins = distributionConfig.Origins;

      if (!origins || !Array.isArray(origins)) {
        return null;
      }

      for (let i = 0; i < origins.length; i++) {
        const origin = origins[i];
        const domainName = origin.DomainName;

        // Check if this is an S3 origin
        const isS3Origin = this.isS3Origin(origin);

        if (isS3Origin) {
          // Check if Origin Access Control is configured
          const originAccessControlId = origin.OriginAccessControlId;

          // Check if Origin Access Identity is configured (legacy approach)
          const s3OriginConfig = origin.S3OriginConfig;
          const originAccessIdentity = s3OriginConfig?.OriginAccessIdentity;

          // Check if alternative S3 security is in place
          let hasAlternativeSecurity = false;
          if (allResources) {
            hasAlternativeSecurity = this.hasAlternativeS3Security(resource, origin, allResources);
          }

          // If neither OAC, OAI, nor alternative security is configured, flag it
          if (!originAccessControlId && !originAccessIdentity && !hasAlternativeSecurity) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description} (Origin[${i}] with domain ${domainName} has no Origin Access Control or Origin Access Identity)`,
              `Add OriginAccessControlId to the origin configuration.`
            );
          }

          // If OAI is used instead of OAC, recommend upgrading to OAC
          if (!originAccessControlId && originAccessIdentity && !hasAlternativeSecurity) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description} (Origin[${i}] with domain ${domainName} uses legacy Origin Access Identity)`,
              `Consider upgrading to Origin Access Control by adding OriginAccessControlId to the origin configuration.`,
              'MEDIUM' // Lower priority since OAI still provides security, but OAC is recommended
            );
          }
        }
      }
    }

    return null;
  }

  private isS3Origin(origin: any): boolean {
    // Check if this is an S3 origin
    if (origin.S3OriginConfig) {
      return true;
    }

    // Check domain name for S3 patterns
    const domainName = origin.DomainName;

    if (typeof domainName === 'string') {
      // Check for various S3 domain formats
      if (domainName.includes('.s3.') && domainName.includes('.amazonaws.com')) {
        return true;
      }

      if (domainName.includes('.s3-website.') && domainName.includes('.amazonaws.com')) {
        return true;
      }

      if (domainName.endsWith('.s3.amazonaws.com')) {
        return true;
      }
    }

    return false;
  }

  private hasAlternativeS3Security(
    distribution: CloudFormationResource,
    origin: any,
    allResources?: CloudFormationResource[]
  ): boolean {
    if (!allResources) {
      return false;
    }

    // Extract the S3 bucket name from the origin domain name
    const domainName = origin.DomainName;
    let bucketName = '';

    if (typeof domainName === 'string') {
      // Extract bucket name from various S3 domain formats
      // Format: my-bucket.s3.amazonaws.com
      let match = domainName.match(/^([^.]+)\.s3\.amazonaws\.com/);
      if (match && match[1]) {
        bucketName = match[1];
      }

      // Format: my-bucket.s3.region.amazonaws.com
      if (!bucketName) {
        match = domainName.match(/^([^.]+)\.s3\.[^.]+\.amazonaws\.com/);
        if (match && match[1]) {
          bucketName = match[1];
        }
      }

      // Format: my-bucket.s3-website.region.amazonaws.com
      if (!bucketName) {
        match = domainName.match(/^([^.]+)\.s3-website\.[^.]+\.amazonaws\.com/);
        if (match && match[1]) {
          bucketName = match[1];
        }
      }
    } else if (typeof domainName === 'object' && domainName['Fn::GetAtt']) {
      // Handle GetAtt references like { "Fn::GetAtt": ["MyBucket", "DomainName"] }
      const getAtt = domainName['Fn::GetAtt'];
      if (Array.isArray(getAtt) && getAtt.length > 0) {
        bucketName = getAtt[0];
      }
    } else if (typeof domainName === 'object' && domainName['Fn::Join']) {
      // Handle Join references like { "Fn::Join": ["", ["myBucket", ".s3.amazonaws.com"]] }
      const join = domainName['Fn::Join'];
      if (Array.isArray(join) && join.length > 1 && Array.isArray(join[1]) && join[1].length > 0) {
        // Try to find the bucket name in the join array
        for (const part of join[1]) {
          if (typeof part === 'string' && !part.includes('.')) {
            bucketName = part;
            break;
          } else if (typeof part === 'object' && part.Ref) {
            bucketName = part.Ref;
            break;
          }
        }
      }
    }

    // Also check if the origin has an explicit S3 bucket reference
    if (!bucketName && origin.S3OriginConfig && origin.S3OriginConfig.OriginAccessIdentity) {
      // If there's an OAI, the origin is definitely an S3 bucket
      // Try to extract the bucket name from the ID field if available
      const id = origin.Id;
      if (typeof id === 'string' && !id.includes('.')) {
        bucketName = id;
      }
    }

    if (!bucketName) {
      return false;
    }

    // Find the S3 bucket in the resources
    const s3Buckets = allResources.filter(r =>
      r.Type === 'AWS::S3::Bucket' &&
      (r.LogicalId === bucketName || r.Properties?.BucketName === bucketName)
    );

    if (s3Buckets.length === 0) {
      return false;
    }

    // Check if the bucket has a bucket policy that grants access to CloudFront
    const bucketPolicies = allResources.filter(r =>
      r.Type === 'AWS::S3::BucketPolicy' &&
      r.Properties?.Bucket
    );

    for (const policy of bucketPolicies) {
      const policyBucket = policy.Properties.Bucket;

      // Check if this policy is for our bucket
      let isForOurBucket = false;

      if (typeof policyBucket === 'string' && policyBucket === bucketName) {
        isForOurBucket = true;
      } else if (typeof policyBucket === 'object' && policyBucket.Ref && policyBucket.Ref === bucketName) {
        isForOurBucket = true;
      }

      if (!isForOurBucket) {
        continue;
      }

      // Check if the policy grants access to CloudFront
      const policyDocument = policy.Properties.PolicyDocument;

      if (!policyDocument || !policyDocument.Statement) {
        continue;
      }

      const statements = Array.isArray(policyDocument.Statement) ?
        policyDocument.Statement :
        [policyDocument.Statement];

      for (const statement of statements) {
        if (statement.Effect !== 'Allow') {
          continue;
        }

        // Check if the principal is CloudFront
        const principal = statement.Principal;

        if (principal) {
          if (principal.Service === 'cloudfront.amazonaws.com' ||
            (Array.isArray(principal.Service) && principal.Service.includes('cloudfront.amazonaws.com'))) {
            return true;
          }
        }

        // Check if the condition includes CloudFront
        const condition = statement.Condition;

        if (condition) {
          // Check for AWS:SourceArn with cloudfront
          if (condition.StringEquals) {
            const sourceArn = condition.StringEquals['AWS:SourceArn'] || condition.StringEquals['aws:SourceArn'];

            if (sourceArn) {
              if (typeof sourceArn === 'string' && sourceArn.includes('cloudfront')) {
                return true;
              }

              if (Array.isArray(sourceArn) && sourceArn.some((arn: string) => arn.includes('cloudfront'))) {
                return true;
              }
            }
          }

          // Check for other condition keys that might reference CloudFront
          if (condition.StringLike) {
            const sourceArn = condition.StringLike['AWS:SourceArn'] || condition.StringLike['aws:SourceArn'];

            if (sourceArn) {
              if (typeof sourceArn === 'string' && sourceArn.includes('cloudfront')) {
                return true;
              }

              if (Array.isArray(sourceArn) && sourceArn.some((arn: string) => arn.includes('cloudfront'))) {
                return true;
              }
            }
          }
        }
      }
    }

    return false;
  }

  // Override the createScanResult method to support different priority levels
  protected createScanResult(
    resource: CloudFormationResource,
    stackName: string,
    issue: string,
    fix: string,
    priority?: 'HIGH' | 'MEDIUM' | 'LOW'
  ): ScanResult {
    return {
      source: 'security-matrix',
      stack: stackName,
      resourceType: resource.Type,
      resourceName: resource.LogicalId,
      issue: issue,
      fix: fix,
      priority: (priority || this.priority).toLowerCase(),
      check_id: this.id,
      status: 'Open'
    };
  }
}

export default new CFR006Rule();
