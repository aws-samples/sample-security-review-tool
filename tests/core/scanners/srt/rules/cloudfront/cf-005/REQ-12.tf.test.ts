import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 Terraform - REQ-12: unresolvable custom origin protocol policy', () => {
  it('passes when origin_protocol_policy is null (unknown at plan time)', () => {
    // When a Terraform value is unknown at plan time (e.g. driven by a variable
    // without a default, or a computed attribute from another resource), the
    // plan reader records it as `null` (or omits the key). The adapter only
    // treats strings as protocolPolicy, so the inspection's protocolPolicy is
    // `undefined`. We supply a secure SSL protocol list so the only ambiguity
    // under test is the protocol policy itself.
    const resource: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'dist',
      address: 'aws_cloudfront_distribution.dist',
      values: {
        origin: [
          {
            origin_id: 'custom-origin-1',
            domain_name: 'example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: null,
                origin_ssl_protocols: ['TLSv1.2'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const adapter = new Cf005TfAdapterFactory().bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when origin_protocol_policy key is absent (unknown at plan time)', () => {
    const resource: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'dist',
      address: 'aws_cloudfront_distribution.dist',
      values: {
        origin: [
          {
            origin_id: 'custom-origin-1',
            domain_name: 'example.com',
            custom_origin_config: [
              {
                // origin_protocol_policy intentionally omitted — unknown at plan time
                origin_ssl_protocols: ['TLSv1.2'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const adapter = new Cf005TfAdapterFactory().bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
