import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002TfAdapterFactory();
const BUCKET_NAME = 'athena-results-bucket';

/**
 * `secureTransportValue` is the value asserted for aws:SecureTransport in the Deny statement:
 *  - 'false' -> Deny fires on non-TLS requests (qualifying TLS enforcement)
 *  - 'true'  -> Deny fires only on TLS requests (no TLS enforcement)
 */
function policyJson(secureTransportValue: string): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AllowAnalystRead',
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::123456789012:role/Analyst' },
        Action: ['s3:GetObject', 's3:ListBucket'],
        Resource: [`arn:aws:s3:::${BUCKET_NAME}`, `arn:aws:s3:::${BUCKET_NAME}/*`],
      },
      {
        Sid: 'DenyUnEncryptedTransport',
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:*',
        Resource: [`arn:aws:s3:::${BUCKET_NAME}`, `arn:aws:s3:::${BUCKET_NAME}/*`],
        Condition: { Bool: { 'aws:SecureTransport': secureTransportValue } },
      },
      {
        Sid: 'DenyIncorrectEncryptionHeader',
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:PutObject',
        Resource: `arn:aws:s3:::${BUCKET_NAME}/*`,
        Condition: { StringNotEquals: { 's3:x-amz-server-side-encryption': 'aws:kms' } },
      },
    ],
  });
}

const bucket: TerraformResource = {
  type: 'aws_s3_bucket',
  name: 'results',
  address: 'aws_s3_bucket.results',
  values: { bucket: BUCKET_NAME },
} as unknown as TerraformResource;

const workgroup: TerraformResource = {
  type: 'aws_athena_workgroup',
  name: 'analytics',
  address: 'aws_athena_workgroup.analytics',
  values: {
    name: 'analytics',
    configuration: [
      { result_configuration: [{ output_location: `s3://${BUCKET_NAME}/query-results/` }] },
    ],
  },
} as unknown as TerraformResource;

// Reference form: HCL wrote `bucket = aws_s3_bucket.results.id`, collapsed to the address.
function bucketPolicy(secureTransportValue: string): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: { bucket: 'aws_s3_bucket.results', policy: policyJson(secureTransportValue) },
  } as unknown as TerraformResource;
}

function evaluateWorkGroup(secureTransportValue: string) {
  const allResources = [workgroup, bucket, bucketPolicy(secureTransportValue)];
  const context: TfContext = {
    projectName: 'test-project',
    resource: workgroup,
    allResources,
  };
  return ath002Control.run(factory.bind(context), context);
}

describe('ATH-002 REQ-12 (Terraform): secure-transport Deny among unrelated statements', () => {
  // Primary behavior owned by this requirement.
  it('passes when the results bucket policy contains a qualifying secure-transport Deny alongside unrelated statements', () => {
    expect(evaluateWorkGroup('false')).toBeNull();
  });

  it('flags when the same multi-statement policy has no Deny that fires on non-TLS requests', () => {
    const result = evaluateWorkGroup('true');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });
});
