import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * CFR005 Rule: For non-AWS origins, encrypt traffic from the origin to the CloudFront distribution using the most recent TLS profile the customer accepts.
 * 
 * Documentation: "Ensure that solution CloudFront distributions use a security policy with minimum TLSv1.1 or TLSv1.2 and appropriate security ciphers for HTTPS viewer connections. A security policy determines two settings: the SSL/TLS protocol that CloudFront uses to communicate with the users and the cipher that CloudFront uses to encrypt the content that it returns to users."
 * 
 * Note: This rule provides unique value not covered by existing Checkov rules by specifically checking the security of connections
 * between CloudFront and non-AWS origins. It ensures that OriginProtocolPolicy is set to 'https-only' and that secure TLS versions
 * are specified in OriginSSLProtocols.
 */
export class CFR005Rule extends BaseRule {
  constructor() {
    super(
      'CFR-005',
      'HIGH',
      'CloudFront distribution with non-AWS origin lacks proper TLS configuration',
      ['AWS::CloudFront::Distribution']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::CloudFront::Distribution') {
      const distributionConfig = resource.Properties?.DistributionConfig;

      if (!distributionConfig) {
        return null;
      }

      // Check origins for non-AWS origins
      const origins = distributionConfig.Origins;

      if (!origins || !Array.isArray(origins)) {
        return null;
      }

      // First check for any http-only origins, which are the most insecure
      for (let i = 0; i < origins.length; i++) {
        const origin = origins[i];

        // Skip S3 origins as they're covered by CFR6
        if (origin.S3OriginConfig) {
          continue;
        }

        // Check custom origins
        const customOriginConfig = origin.CustomOriginConfig;

        if (customOriginConfig) {
          // Check if HTTPS is required for origin communication
          const originProtocolPolicy = customOriginConfig.OriginProtocolPolicy;

          if (originProtocolPolicy === 'http-only') {
            return this.createScanResult(
              resource,
              stackName,
              `CloudFront distribution uses insecure HTTP for origin (Origin[${i}] uses http-only)`,
              `Set OriginProtocolPolicy to 'https-only' for all custom origins.`
            );
          }
        }
      }

      // Then check for match-viewer origins
      for (let i = 0; i < origins.length; i++) {
        const origin = origins[i];

        // Skip S3 origins as they're covered by CFR6
        if (origin.S3OriginConfig) {
          continue;
        }

        // Check custom origins
        const customOriginConfig = origin.CustomOriginConfig;

        if (customOriginConfig) {
          // Check if HTTPS is required for origin communication
          const originProtocolPolicy = customOriginConfig.OriginProtocolPolicy;

          if (originProtocolPolicy === 'match-viewer') {
            return this.createScanResult(
              resource,
              stackName,
              `CloudFront distribution uses match-viewer protocol policy (Origin[${i}] uses match-viewer)`,
              `Set OriginProtocolPolicy to 'https-only' for all custom origins.`
            );
          }
        }
      }

      // Finally check for https-only origins with insecure TLS versions
      for (let i = 0; i < origins.length; i++) {
        const origin = origins[i];

        // Skip S3 origins as they're covered by CFR6
        if (origin.S3OriginConfig) {
          continue;
        }

        // Check custom origins
        const customOriginConfig = origin.CustomOriginConfig;

        if (customOriginConfig) {
          // Check if HTTPS is required for origin communication
          const originProtocolPolicy = customOriginConfig.OriginProtocolPolicy;

          // If the protocol policy is https-only, check the SSL protocols
          if (originProtocolPolicy === 'https-only') {
            // Check if a secure TLS version is specified
            const originSslProtocols = customOriginConfig.OriginSSLProtocols;

            // If no SSL protocols are specified, AWS defaults to secure protocols, so we don't need to flag this
            if (!originSslProtocols || !Array.isArray(originSslProtocols) || originSslProtocols.length === 0) {
              // Skip this check
              continue;
            }

            // Check if insecure protocols are allowed
            if (originSslProtocols.includes('SSLv3') || originSslProtocols.includes('TLSv1')) {
              return this.createScanResult(
                resource,
                stackName,
                `CloudFront distribution uses outdated TLS versions (Origin[${i}] allows SSLv3 or TLSv1)`,
                `Remove 'SSLv3' and 'TLSv1' from OriginSSLProtocols and use at least TLSv1.1 or TLSv1.2.`
              );
            }

            // Check if at least one secure protocol is specified
            if (!originSslProtocols.includes('TLSv1.1') &&
              !originSslProtocols.includes('TLSv1.2') &&
              !originSslProtocols.includes('TLSv1.3')) {
              return this.createScanResult(
                resource,
                stackName,
                `${this.description} (Origin[${i}] does not use secure TLS protocols)`,
                `Include at least 'TLSv1.1', 'TLSv1.2', or 'TLSv1.3' in OriginSSLProtocols.`
              );
            }
          }
        }
      }
    }

    return null;
  }
}

export default new CFR005Rule();
