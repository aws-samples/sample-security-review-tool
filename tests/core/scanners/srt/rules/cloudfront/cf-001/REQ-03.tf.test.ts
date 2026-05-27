import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const TLS_POLICIES = [
  'TLSv1.2_2018',
  'TLSv1.2_2019',
  'TLSv1.2_2021',
  'TLSv1.2_2025',
  'TLSv1.3_2025',
];

describe('CF-001 REQ-03 (Terraform): explicit TLS 1.2+ minimum protocol version passes', () => {
  for (const policy of TLS_POLICIES) {
    it(`passes when viewer_certificate.minimum_protocol_version is ${policy}`, () => {
      const resource: TerraformResource = {
        address: 'aws_cloudfront_distribution.my_distribution',
        type: 'aws_cloudfront_distribution',
        name: 'my_distribution',
        mode: 'managed',
        provider_name: 'registry.terraform.io/hashicorp/aws',
        values: {
          enabled: true,
          viewer_certificate: [
            {
              acm_certificate_arn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
              ssl_support_method: 'sni-only',
              minimum_protocol_version: policy,
            },
          ],
        },
      } as unknown as TerraformResource;

      const context: TfContext = {
        projectName: 'test-project',
        resource,
        allResources: [resource],
      };

      const factory = new Cf001TfAdapterFactory();
      expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

      const adapter = factory.bind(context);
      const result = cf001Control.run(adapter, context);

      expect(result).toBeNull();
    });
  }
});
