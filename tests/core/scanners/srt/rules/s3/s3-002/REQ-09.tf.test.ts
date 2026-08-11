import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (Terraform)
 * Scenario: Bucket policy allow statement grants access to a federated identity
 * provider (SAML/OIDC) identified by a specific provider ARN.
 * Expected: pass (no finding). A federated principal identified by a specific
 * provider ARN is an explicit, named trust relationship — analogous to naming
 * an IAM principal.
 */
describe('S3-002 REQ-09 [Terraform]: federated principal with specific provider ARN', () => {
  it('passes (no finding) for a SAML federated provider ARN in an aws_s3_bucket_policy', () => {
    const policyDoc = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            Federated: 'arn:aws:iam::123456789012:saml-provider/MySAMLProvider',
          },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    };

    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    } as unknown as TerraformResource;

    const bucketPolicy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'site',
      address: 'aws_s3_bucket_policy.site',
      values: {
        // Reference form: field collapses to the target resource's address
        bucket: 'aws_s3_bucket.site',
        policy: JSON.stringify(policyDoc),
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucketPolicy,
      allResources: [bucket, bucketPolicy],
    };

    const factory = new S3002TfAdapterFactory();
    expect(factory.appliesTo(bucketPolicy.type)).toBe(true);
    const adapter = factory.bind(context);

    const result = s3002Control.run(adapter, context);
    expect(result).toBeNull();
  });

  it('passes (no finding) for an OIDC federated provider ARN in an aws_s3_bucket_policy', () => {
    const policyDoc = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            Federated:
              'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com',
          },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    };

    const bucketPolicy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'site',
      address: 'aws_s3_bucket_policy.site',
      values: {
        bucket: 'aws_s3_bucket.site',
        policy: JSON.stringify(policyDoc),
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucketPolicy,
      allResources: [bucketPolicy],
    };

    const factory = new S3002TfAdapterFactory();
    const adapter = factory.bind(context);

    const result = s3002Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
