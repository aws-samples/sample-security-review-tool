import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.tf.js';
import { TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 Terraform - REQ-11: Default cache behavior allow-all with compliant ordered behaviors', () => {
  it('flags the distribution because the default cache behavior is allow-all even when ordered behaviors enforce HTTPS', () => {
    const resource = {
      address: 'aws_cloudfront_distribution.non_compliant',
      type: 'aws_cloudfront_distribution',
      name: 'non_compliant',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        enabled: true,
        default_cache_behavior: [
          {
            target_origin_id: 'origin1',
            viewer_protocol_policy: 'allow-all',
          },
        ],
        ordered_cache_behavior: [
          {
            path_pattern: '/api/*',
            target_origin_id: 'origin1',
            viewer_protocol_policy: 'redirect-to-https',
          },
          {
            path_pattern: '/secure/*',
            target_origin_id: 'origin1',
            viewer_protocol_policy: 'https-only',
          },
        ],
        origin: [
          {
            origin_id: 'origin1',
            domain_name: 'example.com',
          },
        ],
      },
    };

    const context: TfContext = {
      projectName: 'test-project',
      resource: resource as unknown as TfContext['resource'],
      allResources: [resource as unknown as TfContext['resource']],
    };

    const factory = new Cf004TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-004');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.non_compliant');
    expect(result?.status).toBe('Open');
    expect(result?.issue).toContain('default cache behavior');
    expect(result?.issue?.toLowerCase()).toContain('http');
  });
});
