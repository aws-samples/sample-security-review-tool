import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (ATH-002): the secure-transport Deny on the Athena results bucket must cover
 * bucket-level operations as well as object-level ones. A Deny scoped only to
 * "arn:aws:s3:::bucket/*" leaves bucket-level calls reachable over plain HTTP => flag.
 */

const BUCKET_NAME = 'athena-results-bucket';
const BUCKET_ARN = `arn:aws:s3:::${BUCKET_NAME}`;
const OUTPUT_LOCATION = `s3://${BUCKET_NAME}/results/`;

function policyJson(denyResourceScope: unknown): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'DenyInsecureTransport',
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:*',
        Resource: denyResourceScope,
        Condition: { Bool: { 'aws:SecureTransport': 'false' } },
      },
    ],
  });
}

const workgroup: TerraformResource = {
  type: 'aws_athena_workgroup',
  name: 'analytics',
  address: 'aws_athena_workgroup.analytics',
  values: {
    name: 'analytics',
    configuration: [{ result_configuration: [{ output_location: OUTPUT_LOCATION }] }],
  },
} as unknown as TerraformResource;

const bucket: TerraformResource = {
  type: 'aws_s3_bucket',
  name: 'results',
  address: 'aws_s3_bucket.results',
  values: { bucket: BUCKET_NAME },
} as unknown as TerraformResource;

/** Reference form: HCL wrote `bucket = aws_s3_bucket.results.id`. */
function referencePolicy(denyResourceScope: unknown): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: { bucket: 'aws_s3_bucket.results', policy: policyJson(denyResourceScope) },
  } as unknown as TerraformResource;
}

/** Literal form: HCL wrote the bucket name as a string. */
function literalPolicy(denyResourceScope: unknown): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: { bucket: BUCKET_NAME, policy: policyJson(denyResourceScope) },
  } as unknown as TerraformResource;
}

function runControl(policy: TerraformResource): ScanResult | null {
  const allResources = [workgroup, bucket, policy];
  const context: TfContext = { projectName: 'test-project', resource: workgroup, allResources };
  const adapter = new Ath002TfAdapterFactory().bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

describe('ATH-002 REQ-06 (Terraform): secure-transport Deny scope must cover the bucket itself', () => {
  it('flags a workgroup whose results-bucket Deny is scoped only to the objects inside the bucket (reference form)', () => {
    const result = runControl(referencePolicy(`${BUCKET_ARN}/*`));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
    expect(result?.issue).toMatch(/TLS/i);
  });

  it('flags an object-only Deny when the policy names the bucket literally', () => {
    const result = runControl(literalPolicy([`${BUCKET_ARN}/*`]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
  });

  // Opposite outcome: identical fixture except the Deny scope also covers the bucket ARN.
  it('does not flag when the Deny scope covers both the bucket ARN and the object ARN', () => {
    const result = runControl(referencePolicy([BUCKET_ARN, `${BUCKET_ARN}/*`]));

    expect(result).toBeNull();
  });
});
