import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 Terraform - REQ-10: distribution missing default viewer protocol policy and no ordered cache behaviors', () => {
  it('flags the distribution with the missing-default-viewer-protocol-policy scenario', () => {
    const resource: TerraformResource = {
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
            target_origin_id: 'origin-1',
            // No viewer_protocol_policy set
          },
        ],
        // No ordered_cache_behavior collection populated
        origin: [
          {
            origin_id: 'origin-1',
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
    expect(factory.appliesTo(resource.type)).toBe(true);

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-004');
    expect(result!.resourceType).toBe('aws_cloudfront_distribution');
    expect(result!.resourceName).toBe('aws_cloudfront_distribution.my_distribution');
    expect(result!.status).toBe('Open');
    expect(result!.issue).toBe(
      'CloudFront distribution default cache behavior does not specify a viewer protocol policy, allowing plaintext HTTP traffic.'
    );
    expect(result!.fix).toBe(
      'Enforce HTTPS on the distribution default cache behavior by requiring viewers to use HTTPS or be redirected to HTTPS.'
    );
  });
});
