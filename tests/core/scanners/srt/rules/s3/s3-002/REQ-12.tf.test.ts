import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 Terraform - wildcard principal with unresolvable Effect', () => {
  it('passes when the statement Effect is not resolvable to a string (non-string / unknown) even with a wildcard principal', () => {
    // Represent an unresolvable Effect at analysis time by having the parsed statement's
    // Effect be a non-string value (an object/null-like placeholder). The rule's isAllow
    // check requires `typeof effect === 'string'`, so it cannot assert Allow → pass.
    //
    // In Terraform, policies are usually JSON strings. To simulate an "unresolvable" Effect
    // while still keeping the wildcard principal observable to the rule, we hand the adapter
    // a pre-parsed object policy where Effect is not a string.
    const policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          // Effect is an object rather than a resolved string — the analysis-time value is unknown.
          Effect: { unresolved: true },
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    };

    const resource: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'site',
      address: 'aws_s3_bucket_policy.site',
      values: {
        bucket: 'aws_s3_bucket.site',
        policy: policyDocument,
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const factory = new S3002TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket_policy')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
