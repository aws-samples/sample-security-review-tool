import { describe, it, expect } from 'vitest';
import { cf002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-002/cf-002.control.js';
import { Cf002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-002/cf-002.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-002 REQ-04 (Terraform): WAF Classic web ACL ID association satisfies the rule', () => {
  it('passes when aws_cloudfront_distribution is associated with a WAF Classic web ACL via its ACL ID', () => {
    const distribution: TerraformResource = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      schema_version: 0,
      values: {
        enabled: true,
        // WAF Classic web ACL ID (UUID format)
        web_acl_id: 'a1b2c3d4-5678-90ab-cdef-EXAMPLE11111',
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const factory = new Cf002TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
