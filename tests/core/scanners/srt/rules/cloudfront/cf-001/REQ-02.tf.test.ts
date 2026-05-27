import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-001 Terraform - REQ-02: viewer_certificate present but minimum_protocol_version missing', () => {
  it('flags an aws_cloudfront_distribution that declares viewer_certificate without minimum_protocol_version', () => {
    const resource: TerraformResource = {
      address: 'aws_cloudfront_distribution.dist',
      type: 'aws_cloudfront_distribution',
      name: 'dist',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        enabled: true,
        viewer_certificate: [
          {
            // Intentionally missing minimum_protocol_version
            acm_certificate_arn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
            ssl_support_method: 'sni-only',
          },
        ],
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

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-001');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.dist');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });
});
