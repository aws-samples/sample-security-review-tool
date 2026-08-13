import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-15 (ATH-002): An Athena workgroup's results bucket policy that only grants
 * access CONDITIONED on aws:SecureTransport (a conditional Allow) — with no Deny
 * statement for requests lacking secure transport — must still be flagged.
 */

const CONDITIONAL_ALLOW_ONLY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'AllowOnlyOverTls',
      Effect: 'Allow',
      Principal: { AWS: 'arn:aws:iam::123456789012:root' },
      Action: 's3:*',
      Resource: ['arn:aws:s3:::athena-results', 'arn:aws:s3:::athena-results/*'],
      Condition: { Bool: { 'aws:SecureTransport': 'true' } },
    },
  ],
});

const EXPLICIT_DENY_INSECURE = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'DenyInsecureTransport',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: ['arn:aws:s3:::athena-results', 'arn:aws:s3:::athena-results/*'],
      Condition: { Bool: { 'aws:SecureTransport': 'false' } },
    },
  ],
});

const resultsBucket: TerraformResource = {
  type: 'aws_s3_bucket',
  name: 'results',
  address: 'aws_s3_bucket.results',
  values: { bucket: 'athena-results' },
} as unknown as TerraformResource;

function workgroup(outputLocation: string): TerraformResource {
  return {
    type: 'aws_athena_workgroup',
    name: 'analytics',
    address: 'aws_athena_workgroup.analytics',
    values: {
      name: 'analytics',
      configuration: [{ result_configuration: [{ output_location: outputLocation }] }],
    },
  } as unknown as TerraformResource;
}

function bucketPolicy(bucket: string, policy: string): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: { bucket, policy },
  } as unknown as TerraformResource;
}

function run(wg: TerraformResource, policyResource: TerraformResource) {
  const allResources = [wg, resultsBucket, policyResource];
  const context: TfContext = { projectName: 'test-project', resource: wg, allResources };
  const adapter = new Ath002TfAdapterFactory().bind(context);
  return ath002Control.run(adapter, context);
}

describe('ATH-002 REQ-15 (Terraform)', () => {
  it('flags a workgroup whose results bucket policy only conditions an Allow on aws:SecureTransport (literal form)', () => {
    const result = run(
      workgroup('s3://athena-results/query-output/'),
      bucketPolicy('athena-results', CONDITIONAL_ALLOW_ONLY),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
  });

  it('flags the same allow-only policy when the results bucket is wired by reference (reference form)', () => {
    // output_location / bucket written as aws_s3_bucket.results references collapse to the address.
    const result = run(
      workgroup('aws_s3_bucket.results'),
      bucketPolicy('aws_s3_bucket.results', CONDITIONAL_ALLOW_ONLY),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
  });

  // Opposite outcome: identical fixture except the statement is an explicit Deny
  // on requests lacking secure transport — the form the requirement demands.
  it('does not flag when the same bucket policy denies requests without secure transport', () => {
    expect(
      run(workgroup('aws_s3_bucket.results'), bucketPolicy('aws_s3_bucket.results', EXPLICIT_DENY_INSECURE)),
    ).toBeNull();
  });
});
