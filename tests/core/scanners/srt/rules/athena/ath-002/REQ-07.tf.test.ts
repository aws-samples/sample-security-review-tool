import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (ATH-002): The Deny statement on the Athena results bucket must enforce TLS for
 * ALL requests. A Deny scoped to a single narrow operation (e.g. only object reads) leaves
 * other plaintext operations possible, so the workgroup must still be flagged.
 */

const OUTPUT_LOCATION = 's3://athena-results/query/';
const BUCKET_NAME = 'athena-results';

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

const resultsBucket: TerraformResource = {
  type: 'aws_s3_bucket',
  name: 'results',
  address: 'aws_s3_bucket.results',
  values: { bucket: BUCKET_NAME },
} as unknown as TerraformResource;

function bucketPolicy(action: unknown, resource: unknown, bucketField: string): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: {
      bucket: bucketField,
      policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'DenyInsecureTransport',
            Effect: 'Deny',
            Principal: '*',
            Action: action,
            Resource: resource,
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
          },
        ],
      }),
    },
  } as unknown as TerraformResource;
}

function runOnWorkGroup(policy: TerraformResource): ScanResult | null {
  const allResources = [workgroup, resultsBucket, policy];
  const context: TfContext = {
    projectName: 'analytics-project',
    resource: workgroup,
    allResources,
  };
  const adapter = new Ath002TfAdapterFactory().bind(context);
  return ath002Control.run(adapter, context);
}

describe('ATH-002 REQ-07 (Terraform): TLS Deny must cover all requests', () => {
  it('flags a workgroup whose results bucket policy denies insecure transport for only s3:GetObject (reference form)', () => {
    const result = runOnWorkGroup(
      bucketPolicy('s3:GetObject', `arn:aws:s3:::${BUCKET_NAME}/*`, 'aws_s3_bucket.results'),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });

  it('flags a workgroup whose results bucket policy denies insecure transport for only a narrow write operation (literal bucket name form)', () => {
    const result = runOnWorkGroup(
      bucketPolicy(['s3:PutObject'], `arn:aws:s3:::${BUCKET_NAME}/*`, BUCKET_NAME),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
  });

  // Opposite outcome: identical fixture except the Deny covers all actions on the whole bucket.
  it('does not flag a workgroup whose results bucket policy denies insecure transport for all requests', () => {
    const result = runOnWorkGroup(
      bucketPolicy(
        's3:*',
        [`arn:aws:s3:::${BUCKET_NAME}`, `arn:aws:s3:::${BUCKET_NAME}/*`],
        'aws_s3_bucket.results',
      ),
    );

    expect(result).toBeNull();
  });
});
