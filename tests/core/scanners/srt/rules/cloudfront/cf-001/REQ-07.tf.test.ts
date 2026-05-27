import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-001 Terraform - REQ-07: unknown minimum protocol version is flagged', () => {
  it('flags an aws_cloudfront_distribution whose minimum_protocol_version is an unrecognized/future security policy string', () => {
    const resource: TerraformResource = {
      address: 'aws_cloudfront_distribution.unknown_policy',
      type: 'aws_cloudfront_distribution',
      name: 'unknown_policy',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        enabled: true,
        viewer_certificate: [
          {
            acm_certificate_arn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
            ssl_support_method: 'sni-only',
            minimum_protocol_version: 'TLSv9.9_2099',
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
    expect(factory.appliesTo(resource.type)).toBe(true);

    const adapter = factory.bind(context);
    const result = (cf001Control as unknown as {
      run(a: ReturnType<typeof factory.bind>, c: TfContext): unknown;
    }).run(adapter, context);

    expect(result).not.toBeNull();
    expect(result).toMatchObject({
      check_id: 'CF-001',
      resourceType: 'aws_cloudfront_distribution',
      resourceName: 'aws_cloudfront_distribution.unknown_policy',
      status: 'Open',
    });
  });
});
