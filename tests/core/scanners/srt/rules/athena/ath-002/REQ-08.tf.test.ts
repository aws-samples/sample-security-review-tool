import { describe, it, expect } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { TerraformResource, TfContext, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET_NAME = 'athena-results-bucket';
const OUTPUT_LOCATION = `s3://${BUCKET_NAME}/queries/`;

const workgroup: TerraformResource = {
  type: 'aws_athena_workgroup',
  name: 'analytics',
  address: 'aws_athena_workgroup.analytics',
  values: {
    name: 'analytics',
    configuration: [
      {
        result_configuration: [{ output_location: OUTPUT_LOCATION }],
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

/**
 * `secureTransportValue` controls the polarity of the Deny condition:
 *  - 'false' => denies requests made WITHOUT TLS (the required control)
 *  - 'true'  => inverted: denies requests that DID use TLS, leaving plain HTTP allowed
 */
function policyDocument(secureTransportValue: 'true' | 'false'): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'TransportCondition',
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:*',
        Resource: [`arn:aws:s3:::${BUCKET_NAME}`, `arn:aws:s3:::${BUCKET_NAME}/*`],
        Condition: { Bool: { 'aws:SecureTransport': secureTransportValue } },
      },
    ],
  });
}

/** bucketField is either the resource address (reference form) or the literal bucket name. */
function bucketPolicy(secureTransportValue: 'true' | 'false', bucketField: string): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: { bucket: bucketField, policy: policyDocument(secureTransportValue) },
  } as unknown as TerraformResource;
}

function runWorkGroup(policy: TerraformResource): ScanResult | null {
  const allResources = [workgroup, bucket, policy];
  const context: TfContext = {
    projectName: 'test-project',
    resource: workgroup,
    allResources,
  };
  const adapter = new Ath002TfAdapterFactory().bind(context);
  return ath002Control.run(adapter, context);
}

describe('ATH-002 (Terraform) - inverted aws:SecureTransport condition on results bucket policy', () => {
  // Primary behavior owned by this requirement: a Deny gated on SecureTransport=true
  // is the inverse of the control and must be flagged.
  it('flags the workgroup when the results bucket policy (reference form) denies requests that DO use secure transport', () => {
    const result = runWorkGroup(bucketPolicy('true', 'aws_s3_bucket.results'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });

  it('flags the workgroup when the inverted policy is wired to the bucket by literal name', () => {
    const result = runWorkGroup(bucketPolicy('true', BUCKET_NAME));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
  });

  // Opposite outcome: the nearest input that flips the verdict - the same policy with
  // the condition value corrected to 'false' (denying non-TLS requests).
  it('does not flag when the same Deny statement is correctly gated on aws:SecureTransport false', () => {
    const result = runWorkGroup(bucketPolicy('false', 'aws_s3_bucket.results'));

    expect(result).toBeNull();
  });
});
