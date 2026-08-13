import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002TfAdapterFactory();

function scan(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  return ath002Control.run(factory.bind(context), context);
}

const BUCKET_NAME = 'athena-results-bucket';

const resultsBucket: TerraformResource = {
  type: 'aws_s3_bucket',
  name: 'results',
  address: 'aws_s3_bucket.results',
  values: { bucket: BUCKET_NAME },
} as TerraformResource;

const workGroup: TerraformResource = {
  type: 'aws_athena_workgroup',
  name: 'analytics',
  address: 'aws_athena_workgroup.analytics',
  values: {
    name: 'analytics',
    configuration: [{ result_configuration: [{ output_location: `s3://${BUCKET_NAME}/queries/` }] }],
  },
} as TerraformResource;

/** The AWS-documented "restrict access to only HTTPS requests" bucket policy statement. */
function policyDocument(secureTransportValue: string): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'DenyInsecureTransport',
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:*',
        Resource: [`arn:aws:s3:::${BUCKET_NAME}`, `arn:aws:s3:::${BUCKET_NAME}/*`],
        Condition: { Bool: { 'aws:SecureTransport': secureTransportValue } },
      },
    ],
  });
}

function bucketPolicy(bucketField: string, secureTransportValue: string): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: { bucket: bucketField, policy: policyDocument(secureTransportValue) },
  } as TerraformResource;
}

describe('ATH-002 REQ-03 (Terraform): workgroup results bucket policy denies non-TLS requests', () => {
  it('passes when the policy is wired by reference to the results bucket and denies requests without secure transport', () => {
    // Reference form: bucket = aws_s3_bucket.results.id collapses to the resource address.
    const policy = bucketPolicy('aws_s3_bucket.results', 'false');
    expect(scan(workGroup, [workGroup, resultsBucket, policy])).toBeNull();
  });

  it('passes when the policy names the results bucket literally and denies requests without secure transport', () => {
    const policy = bucketPolicy(BUCKET_NAME, 'false');
    expect(scan(workGroup, [workGroup, resultsBucket, policy])).toBeNull();
  });

  it('OPPOSITE: flags the workgroup when the same policy statement is conditioned on secure transport being true (no TLS enforcement)', () => {
    const policy = bucketPolicy('aws_s3_bucket.results', 'true');

    const result = scan(workGroup, [workGroup, resultsBucket, policy]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });
});
