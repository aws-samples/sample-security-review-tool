import { describe, it, expect } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002TfAdapterFactory();

const workgroup: TerraformResource = {
  type: 'aws_athena_workgroup',
  name: 'analytics',
  address: 'aws_athena_workgroup.analytics',
  values: {
    name: 'analytics',
    configuration: [
      {
        result_configuration: [
          { output_location: 's3://my-results-bucket/results/' },
        ],
      },
    ],
  },
} as unknown as TerraformResource;

const bucket: TerraformResource = {
  type: 'aws_s3_bucket',
  name: 'results',
  address: 'aws_s3_bucket.results',
  values: { bucket: 'my-results-bucket' },
} as unknown as TerraformResource;

function bucketPolicy(statement: unknown): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: {
      // reference form: bucket = aws_s3_bucket.results.id
      bucket: 'aws_s3_bucket.results',
      policy: JSON.stringify({ Version: '2012-10-17', Statement: [statement] }),
    },
  } as unknown as TerraformResource;
}

function runOnWorkGroup(policy: TerraformResource) {
  const allResources = [workgroup, bucket, policy];
  const context: TfContext = {
    projectName: 'test-project',
    resource: workgroup,
    allResources,
  };
  return ath002Control.run(factory.bind(context), context);
}

// Primary behavior for REQ-14 (ATH-002): a broad conditional Deny whose condition
// constrains something other than transport security is not TLS enforcement.
describe('ATH-002 REQ-14 (Terraform): Deny conditioned on a non-transport attribute', () => {
  it('flags a workgroup whose results bucket policy denies based on aws:SourceIp instead of aws:SecureTransport', () => {
    const result = runOnWorkGroup(bucketPolicy({
      Sid: 'DenyOutsideNetwork',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: ['arn:aws:s3:::my-results-bucket', 'arn:aws:s3:::my-results-bucket/*'],
      Condition: {
        NotIpAddress: { 'aws:SourceIp': '203.0.113.0/24' },
      },
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });

  // Opposite outcome: identical broad Deny, but the condition keys on transport security.
  it('does not flag when the same broad Deny is conditioned on aws:SecureTransport', () => {
    const result = runOnWorkGroup(bucketPolicy({
      Sid: 'DenyInsecureTransport',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: ['arn:aws:s3:::my-results-bucket', 'arn:aws:s3:::my-results-bucket/*'],
      Condition: {
        Bool: { 'aws:SecureTransport': 'false' },
      },
    }));

    expect(result).toBeNull();
  });
});
