import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * CFR003 Rule: Enable access logging on Cloudfront distributions.
 * 
 * Documentation: "CloudFront distributions must must activate logging to record requests for content. It is important that these logs can be used in an investigation of an incident."
 * 
 * Note: Basic access logging check is covered by Checkov rule CKV_AWS_86, which checks if CloudFront distribution has access logging enabled.
 * This rule adds value by checking for proper log prefix configuration and ensuring the logging bucket has appropriate lifecycle rules for log retention.
 */
export class CFR003Rule extends BaseRule {
  // Priority levels for different types of logging issues
  private readonly MISSING_LOGGING_PRIORITY = 'HIGH';
  private readonly INCOMPLETE_LOGGING_PRIORITY = 'MEDIUM';

  constructor() {
    super(
      'CFR-003',
      'HIGH',
      'CloudFront distribution does not have access logging enabled with proper retention',
      ['AWS::CloudFront::Distribution']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    if (resource.Type === 'AWS::CloudFront::Distribution') {
      // Collect information about CloudFront distributions and S3 buckets
      const resourceInfo = this.collectResourceInformation(allResources);
      return this.evaluateDistribution(resource, stackName, resourceInfo);
    }

    return null;
  }

  private collectResourceInformation(resources: CloudFormationResource[]): {
    distributions: Map<string, {
      logicalId: string,
      hasLogging: boolean,
      loggingBucketRef: string | null,
      loggingPrefix: string | null,
      includesCookies: boolean,
      loggingConfigured: boolean
    }>;
    buckets: Map<string, {
      logicalId: string,
      name: string | null,
      isLoggingBucket: boolean,
      hasLifecycleRules: boolean,
      associatedDistributions: string[]
    }>;
  } {
    const distributions = new Map<string, {
      logicalId: string,
      hasLogging: boolean,
      loggingBucketRef: string | null,
      loggingPrefix: string | null,
      includesCookies: boolean,
      loggingConfigured: boolean
    }>();

    const buckets = new Map<string, {
      logicalId: string,
      name: string | null,
      isLoggingBucket: boolean,
      hasLifecycleRules: boolean,
      associatedDistributions: string[]
    }>();

    // First pass: collect all CloudFront distributions and S3 buckets
    for (const resource of resources) {
      if (resource.Type === 'AWS::CloudFront::Distribution') {
        const distributionConfig = resource.Properties?.DistributionConfig;
        const logging = distributionConfig?.Logging;

        const hasLogging = !!logging;
        const loggingBucketRef = this.resolveReference(logging?.Bucket);
        const loggingPrefix = logging?.Prefix;
        const includesCookies = logging?.IncludeCookies === true;
        const loggingConfigured = hasLogging && !!loggingBucketRef && !!loggingPrefix;

        distributions.set(resource.LogicalId, {
          logicalId: resource.LogicalId,
          hasLogging,
          loggingBucketRef,
          loggingPrefix,
          includesCookies,
          loggingConfigured
        });
      }
      else if (resource.Type === 'AWS::S3::Bucket') {
        const name = resource.Properties?.BucketName || resource.LogicalId;
        const lifecycleConfiguration = resource.Properties?.LifecycleConfiguration;
        const hasLifecycleRules = !!lifecycleConfiguration &&
          Array.isArray(lifecycleConfiguration.Rules) &&
          lifecycleConfiguration.Rules.length > 0;

        buckets.set(resource.LogicalId, {
          logicalId: resource.LogicalId,
          name: typeof name === 'string' ? name : null,
          isLoggingBucket: false,
          hasLifecycleRules,
          associatedDistributions: []
        });
      }
    }

    // Second pass: associate CloudFront distributions with their logging buckets
    for (const [distId, dist] of distributions) {
      if (dist.loggingBucketRef) {
        // First try to find the bucket by logical ID
        if (buckets.has(dist.loggingBucketRef)) {
          const bucket = buckets.get(dist.loggingBucketRef)!;
          bucket.isLoggingBucket = true;
          bucket.associatedDistributions.push(distId);
        } else {
          // If not found by logical ID, try to find by bucket name
          // Extract bucket name from domain name if it's a domain name
          let bucketName = dist.loggingBucketRef;
          if (bucketName.includes('.s3.')) {
            const match = bucketName.match(/^([^.]+)\.s3\./);
            if (match && match[1]) {
              bucketName = match[1];
            }
          }

          // Find the bucket by name
          for (const [bucketId, bucket] of buckets) {
            if (bucket.name === bucketName) {
              bucket.isLoggingBucket = true;
              bucket.associatedDistributions.push(distId);
              break;
            }
          }
        }
      }
    }

    return { distributions, buckets };
  }

  private evaluateDistribution(
    resource: CloudFormationResource,
    stackName: string,
    resourceInfo: ReturnType<typeof this.collectResourceInformation>
  ): ScanResult | null {
    const { distributions, buckets } = resourceInfo;
    const dist = distributions.get(resource.LogicalId);

    if (!dist) {
      return null;
    }

    // Check if logging is enabled
    if (!dist.hasLogging) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (logging not enabled)`,
        `Enable CloudFront access logging by adding a Logging configuration with a target S3 bucket and a log prefix.

IMPORTANT - S3 Bucket for CloudFront Logs:
1. First check if the template already has an S3 bucket configured as a logging destination (look for buckets referenced in other buckets' LoggingConfiguration.DestinationBucketName or serverAccessLogsBucket)
2. If a logging bucket exists, use it as the CloudFront logging bucket with Prefix 'cloudfront-logs/'
3. If no logging bucket exists, create a dedicated server access logging bucket first with LifecycleConfiguration (use expiration: Duration.days(90) in CDK), then create the CloudFront logging bucket that logs to it with Prefix 'cloudfront-logs/'`,
        this.MISSING_LOGGING_PRIORITY
      );
    }

    // Check if logging bucket is specified
    if (!dist.loggingBucketRef) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (logging bucket not specified)`,
        `Specify a target S3 bucket in the Logging configuration using the Bucket property.`,
        this.INCOMPLETE_LOGGING_PRIORITY
      );
    }

    // Check if logging prefix is specified
    if (!dist.loggingPrefix) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (logging prefix not specified)`,
        `Specify a log prefix in the Logging configuration using the Prefix property.`,
        this.INCOMPLETE_LOGGING_PRIORITY
      );
    }

    // Check if the logging bucket has lifecycle rules for log retention
    let bucketFound = false;
    let hasLifecycleRules = false;

    // First check if we can find the bucket by logical ID
    if (buckets.has(dist.loggingBucketRef)) {
      bucketFound = true;
      hasLifecycleRules = buckets.get(dist.loggingBucketRef)!.hasLifecycleRules;
    } else {
      // If not found by logical ID, try to find by bucket name
      // Extract bucket name from domain name if it's a domain name
      let bucketName = dist.loggingBucketRef;
      if (bucketName.includes('.s3.')) {
        const match = bucketName.match(/^([^.]+)\.s3\./);
        if (match && match[1]) {
          bucketName = match[1];
        }
      }

      // Find the bucket by name
      for (const [bucketId, bucket] of buckets) {
        if (bucket.name === bucketName) {
          bucketFound = true;
          hasLifecycleRules = bucket.hasLifecycleRules;
          break;
        }
      }
    }

    if (bucketFound && !hasLifecycleRules) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (logging bucket has no lifecycle rules for log retention)`,
        `Add LifecycleConfiguration with appropriate expiration rules to the S3 bucket used for CloudFront logs.`,
        this.INCOMPLETE_LOGGING_PRIORITY
      );
    }

    return null;
  }

  private resolveReference(ref: any): string | null {
    if (!ref) {
      return null;
    }

    if (typeof ref === 'string') {
      // If the reference is a string, it might be a bucket domain name
      // Extract the bucket name from the domain name
      const match = ref.match(/^([^.]+)\.s3\./);
      if (match && match[1]) {
        return match[1];
      }
      return ref;
    }

    if (typeof ref === 'object' && ref.Ref) {
      return ref.Ref;
    }

    return null;
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
      path: stackName,
      resourceType: resource.Type,
      resourceName: resource.LogicalId,
      issue: issue,
      fix: fix,
      priority: (priority || this.priority).toLowerCase(),
      check_id: this.id,
      status: 'Open',
      cdkPath: resource.Metadata?.['aws:cdk:path']
    };
  }
}

export default new CFR003Rule();
