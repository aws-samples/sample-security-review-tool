import { describe, expect, it } from 'vitest';

import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002TfAdapterFactory();

const SECURE_TRANSPORT_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'DenyInsecureTransport',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: ['arn:aws:s3:::results-bucket', 'arn:aws:s3:::results-bucket/*'],
      Condition: { Bool: { 'aws:SecureTransport': 'false' } },
    },
  ],
});

const POLICY_WITHOUT_DENY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'AllowAnalysts',
      Effect: 'Allow',
      Principal: { AWS: 'arn:aws:iam::123456789012:root' },
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::results-bucket/*',
    },
  ],
});

const workGroup: TerraformResource = {
  type: 'aws_athena_workgroup',
  name: 'analytics',
  address: 'aws_athena_workgroup.analytics',
  values: {
    name: 'analytics',
    configuration: [
      {
        result_configuration: [{ output_location: 's3://results-bucket/query-results/' }],
      },
    ],
  },
} as unknown as TerraformResource;

const resultsBucket: TerraformResource = {
  type: 'aws_s3_bucket',
  name: 'results',
  address: 'aws_s3_bucket.results',
  values: { bucket: 'results-bucket' },
} as unknown as TerraformResource;

/** Reference form: HCL wrote `bucket = aws_s3_bucket.results.id`, collapsed to the address. */
function bucketPolicy(policy: unknown): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: { bucket: 'aws_s3_bucket.results', policy },
  } as unknown as TerraformResource;
}

function runWorkGroup(policy: unknown) {
  const allResources = [workGroup, resultsBucket, bucketPolicy(policy)];
  const context: TfContext = {
    projectName: 'test-project',
    resource: workGroup,
    allResources,
  };
  return ath002Control.run(factory.bind(context) as never, context);
}

describe('ATH-002 Terraform — secure-transport Deny undeterminable at plan time', () => {
  // Primary behavior owned by this requirement: indeterminate deciding value => no finding.
  it('does not flag when the attached bucket policy document is unknown at plan time (null)', () => {
    expect(runWorkGroup(null)).toBeNull();
  });

  it('does not flag when the attached bucket policy document is omitted from planned values', () => {
    expect(runWorkGroup(undefined)).toBeNull();
  });

  it('does not flag when the resolvable policy does contain the secure-transport Deny', () => {
    expect(runWorkGroup(SECURE_TRANSPORT_POLICY)).toBeNull();
  });

  // Opposite outcome: identical fixture, but the policy is fully known and lacks the Deny.
  it('flags when the known policy document contains no secure-transport Deny statement', () => {
    const result = runWorkGroup(POLICY_WITHOUT_DENY);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });
});
