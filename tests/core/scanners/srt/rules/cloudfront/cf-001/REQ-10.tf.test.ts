import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-001 (Terraform) - REQ-10: custom certificate without minimum protocol version', () => {
  it('flags an aws_cloudfront_distribution that uses a custom ACM certificate but does not specify minimum_protocol_version', () => {
    const resource: TerraformResource = {
      address: 'aws_cloudfront_distribution.example',
      type: 'aws_cloudfront_distribution',
      name: 'example',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        enabled: true,
        viewer_certificate: [
          {
            acm_certificate_arn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
            ssl_support_method: 'sni-only',
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
    expect(result!.check_id).toBe('CF-001');
    expect(result!.resourceType).toBe('aws_cloudfront_distribution');
    expect(result!.resourceName).toBe('aws_cloudfront_distribution.example');
    expect(result!.status).toBe('Open');
    expect(result!.issue).toContain('minimum TLS protocol version');
  });

  it('flags an aws_cloudfront_distribution that uses a custom IAM certificate but does not specify minimum_protocol_version', () => {
    const resource: TerraformResource = {
      address: 'aws_cloudfront_distribution.iam_cert',
      type: 'aws_cloudfront_distribution',
      name: 'iam_cert',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        enabled: true,
        viewer_certificate: [
          {
            iam_certificate_id: 'ASCAEXAMPLE',
            ssl_support_method: 'sni-only',
          },
        ],
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const adapter = new Cf001TfAdapterFactory().bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-001');
    expect(result!.resourceName).toBe('aws_cloudfront_distribution.iam_cert');
    expect(result!.issue).toContain('minimum TLS protocol version');
  });
});
