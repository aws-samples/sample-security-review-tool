import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (Terraform): Bucket policy allow statement grants access to a
 * specific IAM principal identified by an ARN in a named AWS account
 * (same-account or cross-account). Expected: PASS.
 *
 * A named ARN principal is a deliberate, auditable grant. The rule targets
 * non-identifiable (wildcard) principals, not named ones.
 */
describe('S3-002 TF REQ-05: specific ARN principal in named account -> pass', () => {
  const factory = new S3002TfAdapterFactory();

  function buildContext(policyDocument: object): TfContext {
    const resource: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'site',
      address: 'aws_s3_bucket_policy.site',
      values: {
        bucket: 'aws_s3_bucket.site',
        policy: JSON.stringify(policyDocument),
      },
    } as TerraformResource;

    return {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };
  }

  it('passes when Allow grants access to a specific IAM ARN in the same account', () => {
    const context = buildContext({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: 'arn:aws:iam::123456789012:role/AppRole',
          },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    });

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when Allow grants access to a specific IAM ARN in a cross-account (different account id)', () => {
    const context = buildContext({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: 'arn:aws:iam::999988887777:role/PartnerRole',
          },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    });

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when Allow grants access to a list of specific IAM ARNs (all named)', () => {
    const context = buildContext({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: [
              'arn:aws:iam::123456789012:role/AppRole',
              'arn:aws:iam::999988887777:user/PartnerUser',
            ],
          },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    });

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
