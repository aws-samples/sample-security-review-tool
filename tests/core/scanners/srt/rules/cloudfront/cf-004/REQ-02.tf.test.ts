import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 / REQ-02 / Terraform: Default cache behavior allows both HTTP and HTTPS (allow-all)', () => {
  it('flags a distribution whose default cache behavior viewer_protocol_policy is allow-all', () => {
    const resource: TerraformResource = {
      address: 'aws_cloudfront_distribution.insecure',
      type: 'aws_cloudfront_distribution',
      name: 'insecure',
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

    const factory = new Cf004TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-004');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.insecure');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });
});
