import { describe, it, expect } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002TfAdapterFactory();

function runOn(target: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: target,
    allResources,
  };
  return ath002Control.run(factory.bind(context), context);
}

const secureTransportDenyPolicyJson = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'DenyInsecureTransport',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: ['arn:aws:s3:::my-results-bucket', 'arn:aws:s3:::my-results-bucket/*'],
      Condition: { Bool: { 'aws:SecureTransport': 'false' } },
    },
  ],
});

const resultsBucket: TerraformResource = {
  type: 'aws_s3_bucket',
  name: 'results',
  address: 'aws_s3_bucket.results',
  values: { bucket: 'my-results-bucket' },
} as unknown as TerraformResource;

// Reference form - user wrote `bucket = aws_s3_bucket.results.id` in HCL
const bucketPolicyByReference: TerraformResource = {
  type: 'aws_s3_bucket_policy',
  name: 'results',
  address: 'aws_s3_bucket_policy.results',
  values: { bucket: 'aws_s3_bucket.results', policy: secureTransportDenyPolicyJson },
} as unknown as TerraformResource;

describe('ATH-002 (Terraform) - workgroup with no query-result output location', () => {
  // REQ-01 owns this behavior: no output_location => no result bucket can be
  // identified, so the results cannot be shown to be TLS-protected => flag.
  it('flags a workgroup whose result_configuration omits output_location', () => {
    const workgroup: TerraformResource = {
      type: 'aws_athena_workgroup',
      name: 'analytics',
      address: 'aws_athena_workgroup.analytics',
      values: {
        name: 'analytics',
        configuration: [
          {
            enforce_workgroup_configuration: true,
            result_configuration: [
              { encryption_configuration: [{ encryption_option: 'SSE_S3' }] },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const result = runOn(workgroup, [workgroup, resultsBucket, bucketPolicyByReference]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
  });

  it('flags a workgroup with no configuration block at all', () => {
    const workgroup: TerraformResource = {
      type: 'aws_athena_workgroup',
      name: 'analytics',
      address: 'aws_athena_workgroup.analytics',
      values: { name: 'analytics' },
    } as unknown as TerraformResource;

    expect(runOn(workgroup, [workgroup, resultsBucket, bucketPolicyByReference])).not.toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict - same workgroup, but
  // output_location present and pointing at a bucket whose policy denies non-TLS
  // requests. Reference form, as produced when HCL uses aws_s3_bucket.results.id.
  it('does not flag the same workgroup once an output_location with a TLS-denying bucket policy is present (reference form)', () => {
    const workgroup: TerraformResource = {
      type: 'aws_athena_workgroup',
      name: 'analytics',
      address: 'aws_athena_workgroup.analytics',
      values: {
        name: 'analytics',
        configuration: [
          {
            enforce_workgroup_configuration: true,
            result_configuration: [
              {
                output_location: 'aws_s3_bucket.results',
                encryption_configuration: [{ encryption_option: 'SSE_S3' }],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    expect(runOn(workgroup, [workgroup, resultsBucket, bucketPolicyByReference])).toBeNull();
  });

  it('does not flag the same workgroup when output_location is a literal s3 URI for a TLS-protected bucket (literal form)', () => {
    const literalBucketPolicy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'results',
      address: 'aws_s3_bucket_policy.results',
      values: { bucket: 'my-results-bucket', policy: secureTransportDenyPolicyJson },
    } as unknown as TerraformResource;

    const workgroup: TerraformResource = {
      type: 'aws_athena_workgroup',
      name: 'analytics',
      address: 'aws_athena_workgroup.analytics',
      values: {
        name: 'analytics',
        configuration: [
          {
            enforce_workgroup_configuration: true,
            result_configuration: [{ output_location: 's3://my-results-bucket/results/' }],
          },
        ],
      },
    } as unknown as TerraformResource;

    expect(runOn(workgroup, [workgroup, resultsBucket, literalBucketPolicy])).toBeNull();
  });
});
