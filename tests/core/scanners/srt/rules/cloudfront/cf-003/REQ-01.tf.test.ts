import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 Terraform - REQ-01: distribution with no access logging configuration', () => {
  it('flags an aws_cloudfront_distribution with no logging_config block and no external log delivery source referencing it', () => {
    const distribution: TerraformResource = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
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
        // Note: no logging_config block — access logging is disabled.
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [distribution];

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const factory = new Cf003TfAdapterFactory();
    expect(factory.appliesTo(distribution.type)).toBe(true);

    const adapter = factory.bind(context);
    const result = cf003Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-003');
    expect(result!.resourceType).toBe('aws_cloudfront_distribution');
    expect(result!.resourceName).toBe('aws_cloudfront_distribution.my_distribution');
    expect(result!.status).toBe('Open');
  });
});
