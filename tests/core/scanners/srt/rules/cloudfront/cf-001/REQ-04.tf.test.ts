import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-04 (Terraform):
 * Scenario: aws_cloudfront_distribution explicitly sets minimum_protocol_version to a value
 * that permits TLS versions below 1.2 (e.g., SSLv3, TLSv1, TLSv1_2016, TLSv1.1_2016).
 * Expected Behavior: flag
 */

function buildResource(minimumProtocolVersion: string): TerraformResource {
  return {
    address: 'aws_cloudfront_distribution.my_distribution',
    type: 'aws_cloudfront_distribution',
    name: 'my_distribution',
    mode: 'managed',
    provider_name: 'registry.terraform.io/hashicorp/aws',
    schema_version: 0,
    values: {
      enabled: true,
      default_cache_behavior: [
        {
          target_origin_id: 'origin1',
          viewer_protocol_policy: 'redirect-to-https',
        },
      ],
      origin: [
        {
          origin_id: 'origin1',
          domain_name: 'example.com',
        },
      ],
      viewer_certificate: [
        {
          acm_certificate_arn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
          ssl_support_method: 'sni-only',
          minimum_protocol_version: minimumProtocolVersion,
        },
      ],
    },
  } as unknown as TerraformResource;
}

function runControl(resource: TerraformResource) {
  const factory = new Cf001TfAdapterFactory();
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context);
  return cf001Control.run(adapter, context);
}

describe('CF-001 REQ-04 Terraform: minimum_protocol_version below TLS 1.2 should be flagged', () => {
  const insecureProtocolVersions = ['SSLv3', 'TLSv1', 'TLSv1_2016', 'TLSv1.1_2016'];

  for (const version of insecureProtocolVersions) {
    it(`flags an aws_cloudfront_distribution that sets minimum_protocol_version to ${version}`, () => {
      const resource = buildResource(version);
      const result = runControl(resource);

      expect(result).not.toBeNull();
      expect(result?.check_id).toBe('CF-001');
      expect(result?.resourceType).toBe('aws_cloudfront_distribution');
      expect(result?.resourceName).toBe('aws_cloudfront_distribution.my_distribution');
      expect(result?.status).toBe('Open');
    });
  }
});
