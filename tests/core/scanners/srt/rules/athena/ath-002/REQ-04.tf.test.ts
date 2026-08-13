import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * ATH-002 / REQ-04
 * Requirement: an Athena workgroup passes when its S3 output-location bucket is covered by a
 * bucket-policy Deny statement enforcing aws:SecureTransport. This file owns the case where the
 * Deny statement's action and resource scopes are broad wildcards that encompass the bucket and
 * all of its objects -- at least as restrictive as an enumerated scope, therefore a pass.
 */

const factory = new Ath002TfAdapterFactory();

const BUCKET_NAME = 'athena-results-bucket';
const OUTPUT_LOCATION = `s3://${BUCKET_NAME}/query-results/`;

function wildcardDenyPolicy(secureTransportValue: string): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'DenyInsecureTransport',
        Effect: 'Deny',
        Principal: '*',
        Action: '*',
        Resource: '*',
        Condition: { Bool: { 'aws:SecureTransport': secureTransportValue } },
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

function policyResource(bucketField: string, secureTransportValue: string): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: { bucket: bucketField, policy: wildcardDenyPolicy(secureTransportValue) },
  } as unknown as TerraformResource;
}

function runWorkGroup(policy: TerraformResource) {
  const allResources = [workgroup, bucket, policy];
  const context: TfContext = {
    projectName: 'analytics-project',
    resource: workgroup,
    allResources,
  };
  return ath002Control.run(factory.bind(context), context);
}

describe('ATH-002 REQ-04 (Terraform): wildcard-scoped Deny on non-TLS requests', () => {
  it('passes when the policy is wired by reference (aws_s3_bucket.results) and denies wildcard actions without secure transport', () => {
    const result = runWorkGroup(policyResource('aws_s3_bucket.results', 'false'));

    expect(result).toBeNull();
  });

  it('passes when the policy is wired by literal bucket name and denies wildcard actions without secure transport', () => {
    const result = runWorkGroup(policyResource(BUCKET_NAME, 'false'));

    expect(result).toBeNull();
  });

  it('OPPOSITE: flags when the same wildcard Deny statement is conditioned on secure transport being true (does not enforce TLS)', () => {
    const result = runWorkGroup(policyResource('aws_s3_bucket.results', 'true'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });
});
