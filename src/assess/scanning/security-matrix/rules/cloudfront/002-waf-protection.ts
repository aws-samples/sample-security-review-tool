import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * CFR002 Rule: Use AWS WAF on public CloudFront distributions.
 * 
 * Documentation: "Use AWS Web Application Firewall (AWS WAF) to protect against application-layer attacks that can compromise the security of the solution or place unnecessary load on them."
 * 
 * Note: Basic WAF check is covered by Checkov rule CKV_AWS_68, which checks if CloudFront distribution has WAF enabled.
 * This rule adds value by determining if the distribution is public-facing and serves web content before requiring WAF.
 */
export class CFR002Rule extends BaseRule {
  constructor() {
    super(
      'CFR-002',
      'HIGH',
      'CloudFront distribution lacks WAF protection',
      ['AWS::CloudFront::Distribution']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::CloudFront::Distribution') {
      const distributionConfig = resource.Properties?.DistributionConfig;

      if (!distributionConfig) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (missing DistributionConfig)`,
          `Add a DistributionConfig property to the CloudFront distribution`
        );
      }

      // Check if WAF is associated with this distribution
      const webACLId = distributionConfig.WebACLId;

      if (!webACLId) {
        // Check if this is a public-facing distribution that serves web content
        const isPublicWebDistribution = this.isPublicWebDistribution(distributionConfig);

        if (isPublicWebDistribution) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (public-facing web distribution without WAF protection)`,
            `Add a WebACLId property to the DistributionConfig to associate a WAF Web ACL with this distribution`
          );
        }
      }
    }

    return null;
  }

  private isPublicWebDistribution(distributionConfig: any): boolean {
    // Check if this is a public-facing distribution that serves web content

    // First, check if this is an internal/private distribution
    const origins = distributionConfig.Origins;

    if (origins && Array.isArray(origins)) {
      // Check if all origins are private (e.g., S3 with OAI/OAC or custom origins in private networks)
      let allOriginsPrivate = true;

      for (const origin of origins) {
        // Check if this is an S3 origin with OAI/OAC
        const s3OriginConfig = origin.S3OriginConfig;

        if (s3OriginConfig) {
          const originAccessIdentity = s3OriginConfig.OriginAccessIdentity;
          const originAccessControlId = origin.OriginAccessControlId;

          if (!originAccessIdentity && !originAccessControlId) {
            // S3 origin without OAI/OAC is likely public
            allOriginsPrivate = false;
            break;
          }
        }

        // Check if this is a custom origin
        const customOriginConfig = origin.CustomOriginConfig;

        if (customOriginConfig) {
          // If it's a custom origin, it's likely public unless it's in a private network
          // We can't determine this from the CloudFormation template alone
          allOriginsPrivate = false;
          break;
        }
      }

      if (allOriginsPrivate) {
        // If all origins are private, WAF is not strictly necessary
        return false;
      }
    }

    // Check if this distribution serves web content

    // Check for default root object (indicates a website)
    const defaultRootObject = distributionConfig.DefaultRootObject;

    if (defaultRootObject) {
      return true;
    }

    // Check cache behaviors for web content patterns
    const defaultCacheBehavior = distributionConfig.DefaultCacheBehavior;

    if (defaultCacheBehavior) {
      // Check if the default cache behavior might be serving web content
      if (this.cacheBehaviorServesWebContent(defaultCacheBehavior)) {
        return true;
      }
    }

    // Check other cache behaviors
    const cacheBehaviors = distributionConfig.CacheBehaviors;

    if (cacheBehaviors && Array.isArray(cacheBehaviors)) {
      for (const cacheBehavior of cacheBehaviors) {
        if (this.cacheBehaviorServesWebContent(cacheBehavior)) {
          return true;
        }
      }
    }

    // If we can't determine for sure, default to false
    // This is a change from the previous behavior, which defaulted to true
    // We're being more conservative now to avoid false positives
    return false;
  }

  private cacheBehaviorServesWebContent(cacheBehavior: any): boolean {
    // Check if this cache behavior might be serving web content

    // Check path pattern
    const pathPattern = cacheBehavior.PathPattern;

    if (pathPattern) {
      // Check if the path pattern indicates web content
      if (pathPattern === '*' ||
        pathPattern.endsWith('.html') ||
        pathPattern.endsWith('.htm') ||
        pathPattern.endsWith('/') ||
        pathPattern.includes('*/') ||
        pathPattern.includes('*.js') ||
        pathPattern.includes('*.css')) {
        return true;
      }
    } else {
      // Default cache behavior (no path pattern) is likely serving web content
      return true;
    }

    // Check allowed methods
    const allowedMethods = cacheBehavior.AllowedMethods;

    if (allowedMethods && Array.isArray(allowedMethods)) {
      // If it allows POST/PUT methods, it might be a web application
      if (allowedMethods.includes('POST') || allowedMethods.includes('PUT')) {
        return true;
      }
    }

    return false;
  }
}

export default new CFR002Rule();
