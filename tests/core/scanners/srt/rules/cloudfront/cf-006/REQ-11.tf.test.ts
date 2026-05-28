import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (Terraform): A CloudFront distribution has an OAC-eligible non-S3 origin
 * (Lambda function URL, MediaStore, or MediaPackage v2) where the origin_access_control_id
 * value is provided via an unresolvable expression (e.g., a value that the Terraform plan
 * could not evaluate to a string — represented here as a non-string sentinel).
 *
 * Per resolved decision, unresolvable values cannot be asserted as non-compliant on any
 * origin type. Expected behavior: PASS (no finding).
 */
describe('CF-006 REQ-11 (TF): non-S3 OAC-eligible origin with unresolvable origin_access_control_id', () => {
  const factory = new Cf006TfAdapterFactory();

  function runRule(distribution: TerraformResource, allResources: TerraformResource[]) {
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };
    const adapter = factory.bind(context);
    return cf006Control.run(adapter as any, context);
  }

  it('passes when a Lambda Function URL origin has an unresolvable origin_access_control_id', () => {
    const distribution = {
      address: 'aws_cloudfront_distribution.this',
      type: 'aws_cloudfront_distribution',
      name: 'this',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'lambda-origin',
            domain_name: 'abc123.lambda-url.us-east-1.on.aws',
            // Non-string represents an unresolvable expression in the parsed plan
            origin_access_control_id: { __unresolved__: true },
          },
        ],
      },
    } as unknown as TerraformResource;

    const result = runRule(distribution, [distribution]);
    expect(result).toBeNull();
  });

  it('passes when a MediaStore origin has an unresolvable origin_access_control_id', () => {
    const distribution = {
      address: 'aws_cloudfront_distribution.this',
      type: 'aws_cloudfront_distribution',
      name: 'this',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'mediastore-origin',
            domain_name: 'mycontainer.data.mediastore.us-east-1.amazonaws.com',
            origin_access_control_id: { __unresolved__: true },
          },
        ],
      },
    } as unknown as TerraformResource;

    const result = runRule(distribution, [distribution]);
    expect(result).toBeNull();
  });

  it('passes when a MediaPackage v2 origin has an unresolvable origin_access_control_id', () => {
    const distribution = {
      address: 'aws_cloudfront_distribution.this',
      type: 'aws_cloudfront_distribution',
      name: 'this',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'mp2-origin',
            domain_name: 'abcd1234.egress.mediapackagev2.us-east-1.amazonaws.com',
            origin_access_control_id: { __unresolved__: true },
          },
        ],
      },
    } as unknown as TerraformResource;

    const result = runRule(distribution, [distribution]);
    expect(result).toBeNull();
  });
});
