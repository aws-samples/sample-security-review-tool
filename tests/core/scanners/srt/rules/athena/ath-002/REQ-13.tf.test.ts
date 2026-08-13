import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (ATH-002): An Athena workgroup whose results bucket has a bucket policy
 * attached, but whose policy document contains no statements at all, must be flagged.
 * An empty statement list contains no secure-transport Deny, so plaintext HTTP is unblocked.
 */

const BUCKET_NAME = 'athena-results-bucket';

const workgroup: TerraformResource = {
  type: 'aws_athena_workgroup',
  name: 'analytics',
  address: 'aws_athena_workgroup.analytics',
  values: {
    name: 'analytics',
    configuration: [
      {
        result_configuration: [
          {
            output_location: `s3://${BUCKET_NAME}/queries/`,
          },
        ],
      },
    ],
  },
} as unknown as TerraformResource;

const bucket: TerraformResource = {
  type: 'aws_s3_bucket',
  name: 'results',
  address: 'aws_s3_bucket.results',
  values: { bucket: BUCKET_NAME },
} as unknown as TerraformResource;

function policyResource(bucketField: string, statements: unknown[]): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: {
      bucket: bucketField,
      policy: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
    },
  } as unknown as TerraformResource;
}

const SECURE_TRANSPORT_DENY = {
  Sid: 'DenyInsecureTransport',
  Effect: 'Deny',
  Principal: '*',
  Action: 's3:*',
  Resource: [`arn:aws:s3:::${BUCKET_NAME}`, `arn:aws:s3:::${BUCKET_NAME}/*`],
  Condition: { Bool: { 'aws:SecureTransport': 'false' } },
};

function runOnWorkGroup(policy: TerraformResource) {
  const allResources = [workgroup, bucket, policy];
  const context: TfContext = {
    projectName: 'analytics-project',
    resource: workgroup,
    allResources,
  };
  const adapter = new Ath002TfAdapterFactory().bind(context);
  return ath002Control.run(adapter, context);
}

describe('ATH-002 REQ-13 (Terraform): results bucket policy with no statements', () => {
  it('flags the workgroup when the reference-form bucket policy has an empty statement list', () => {
    // reference form: bucket = aws_s3_bucket.results.id collapses to the address string
    const result = runOnWorkGroup(policyResource('aws_s3_bucket.results', []));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
  });

  it('flags the workgroup when the literal-form bucket policy has an empty statement list', () => {
    const result = runOnWorkGroup(policyResource(BUCKET_NAME, []));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
  });

  // Opposite outcome: identical plan except the policy carries the secure-transport Deny.
  it('does not flag the workgroup when the same policy contains a secure-transport Deny statement', () => {
    const result = runOnWorkGroup(policyResource('aws_s3_bucket.results', [SECURE_TRANSPORT_DENY]));

    expect(result).toBeNull();
  });
});
