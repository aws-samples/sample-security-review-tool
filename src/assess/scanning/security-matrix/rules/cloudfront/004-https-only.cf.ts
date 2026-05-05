import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * CFR004 Rule: Always require HTTPS between viewers and CloudFront distributions.
 * 
 * Documentation: "Ensure that solution CloudFront distributions use a security policy with minimum TLSv1.1 or TLSv1.2 and appropriate security ciphers for HTTPS viewer connections. A security policy determines two settings: the SSL/TLS protocol that CloudFront uses to communicate with the users and the cipher that CloudFront uses to encrypt the content that it returns to users."
 * 
 * Note: Basic HTTPS enforcement is covered by Checkov rule CKV_AWS_34, which checks if CloudFront distribution ViewerProtocolPolicy is set to HTTPS.
 * TLS version check is covered by Checkov rule CKV_AWS_174, which verifies CloudFront Distribution Viewer Certificate is using TLS v1.2.
 * This rule adds value by checking both the ViewerProtocolPolicy and MinimumProtocolVersion in a single rule, and providing specific guidance on the required TLS versions.
 */
export class CFR004Rule extends BaseRule {
  constructor() {
    super(
      'CFR-004',
      'HIGH',
      'CloudFront distribution allows insecure HTTP traffic',
      ['AWS::CloudFront::Distribution']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::CloudFront::Distribution') {
      const distributionConfig = resource.Properties?.DistributionConfig;
      if (!distributionConfig) return null;

      // Check default cache behavior
      const defaultCacheBehavior = distributionConfig.DefaultCacheBehavior;
      if (defaultCacheBehavior) {
        const viewerProtocolPolicy = defaultCacheBehavior.ViewerProtocolPolicy;
        if (viewerProtocolPolicy !== 'redirect-to-https' && viewerProtocolPolicy !== 'https-only') {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Set ViewerProtocolPolicy to 'redirect-to-https' or 'https-only' in DefaultCacheBehavior.`
          );
        }
      }

      // Check cache behaviors
      const cacheBehaviors = distributionConfig.CacheBehaviors || [];
      for (const cacheBehavior of cacheBehaviors) {
        const viewerProtocolPolicy = cacheBehavior.ViewerProtocolPolicy;
        if (viewerProtocolPolicy !== 'redirect-to-https' && viewerProtocolPolicy !== 'https-only') {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Set ViewerProtocolPolicy to 'redirect-to-https' or 'https-only' in all CacheBehaviors.`
          );
        }
      }

      // Check minimum TLS version in security policy
      const viewerCertificate = distributionConfig.ViewerCertificate;
      if (viewerCertificate) {
        const minimumProtocolVersion = viewerCertificate.MinimumProtocolVersion;

        // Check if a protocol version is specified
        if (!minimumProtocolVersion) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (no minimum TLS version specified)`,
            `Set MinimumProtocolVersion to at least 'TLSv1.1_2016' in ViewerCertificate.`
          );
        }

        // Check if the protocol version is secure enough
        const insecureProtocols = ['SSLv3', 'TLSv1', 'TLSv1_2016'];
        if (insecureProtocols.includes(minimumProtocolVersion)) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (insecure TLS version '${minimumProtocolVersion}')`,
            `Set MinimumProtocolVersion to at least 'TLSv1.1_2016' in ViewerCertificate.`
          );
        }
      } else {
        // If no viewer certificate is specified, CloudFront uses the default certificate with potentially insecure settings
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (no ViewerCertificate specified)`,
          `Add ViewerCertificate with MinimumProtocolVersion set to at least 'TLSv1.1_2016'.`
        );
      }
    }

    return null;
  }
}

export default new CFR004Rule();
