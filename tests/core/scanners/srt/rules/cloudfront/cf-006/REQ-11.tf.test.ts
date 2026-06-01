import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (Terraform): A CloudFront distribution has an OAC-eligible non-S3 origin
 * (Lambda function URL, MediaStore, or MediaPackage v2) where origin_access_control_id
 * is unknown at plan time. The plan reader records this as null.
 *
 * Expected: pass (no finding) — per resolved decision, unresolvable values cannot be
 * asserted as non-compliant on any origin type.
 */

function runControl(distribution: TerraformResource, allResources: TerraformResource[]) {
  const factory = new Cf006TfAdapterFactory();
  const context: TfContext = {
    projectName: 'test-project',
    resource: distribution,
    allResources,
  };
  const adapter = factory.bind(context);
  return cf006Control.run(adapter, context);
}

describe('CF-006 REQ-11 (TF): non-S3 OAC-eligible origin with unresolvable origin_access_control_id', () => {
  it('passes when a Lambda function URL origin has origin_access_control_id resolved to null', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'cdn',
      address: 'aws_cloudfront_distribution.cdn',
      values: {
        origin: [
          {
            origin_id: 'lambda-origin',
            domain_name: 'abcdef1234.lambda-url.us-east-1.on.aws',
            origin_access_control_id: null,
          },
        ],
      },
    } as TerraformResource;

    const result = runControl(distribution, [distribution]);
    expect(result).toBeNull();
  });

  it('passes when a MediaStore origin has origin_access_control_id resolved to null', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'cdn',
      address: 'aws_cloudfront_distribution.cdn',
      values: {
        origin: [
          {
            origin_id: 'mediastore-origin',
            domain_name: 'mycontainer.data.mediastore.us-east-1.amazonaws.com',
            origin_access_control_id: null,
          },
        ],
      },
    } as TerraformResource;

    const result = runControl(distribution, [distribution]);
    expect(result).toBeNull();
  });

  it('passes when a MediaPackage v2 origin has origin_access_control_id resolved to null', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'cdn',
      address: 'aws_cloudfront_distribution.cdn',
      values: {
        origin: [
          {
            origin_id: 'mediapackagev2-origin',
            domain_name: 'channel.egress.mediapackagev2.us-east-1.amazonaws.com',
            origin_access_control_id: null,
          },
        ],
      },
    } as TerraformResource;

    const result = runControl(distribution, [distribution]);
    expect(result).toBeNull();
  });
});
