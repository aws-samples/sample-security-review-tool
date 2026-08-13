import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002TfAdapterFactory();

const SECURE_TRANSPORT_DENY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'DenyInsecureTransport',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: ['arn:aws:s3:::unrelated-logs-bucket', 'arn:aws:s3:::unrelated-logs-bucket/*'],
      Condition: { Bool: { 'aws:SecureTransport': 'false' } },
    },
  ],
});

const resultsBucket: TerraformResource = {
  type: 'aws_s3_bucket',
  name: 'results',
  address: 'aws_s3_bucket.results',
  values: { bucket: 'wg-results-bucket' },
} as unknown as TerraformResource;

const logsBucket: TerraformResource = {
  type: 'aws_s3_bucket',
  name: 'logs',
  address: 'aws_s3_bucket.logs',
  values: { bucket: 'unrelated-logs-bucket' },
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

function tlsPolicy(bucket: string): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'tls',
    address: 'aws_s3_bucket_policy.tls',
    values: { bucket, policy: SECURE_TRANSPORT_DENY },
  } as unknown as TerraformResource;
}

function runOn(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

describe('ATH-002 Terraform - TLS Deny policy attached to a different bucket (REQ-05)', () => {
  it('flags the workgroup (literal output location) when the Deny policy protects an unrelated bucket', () => {
    const wg = workgroup('s3://wg-results-bucket/query-results/');
    const result = runOn(wg, [wg, resultsBucket, logsBucket, tlsPolicy('unrelated-logs-bucket')]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
  });

  it('flags the workgroup (reference-form output location) when the Deny policy protects an unrelated bucket', () => {
    // output_location = aws_s3_bucket.results.bucket collapses to the bucket address
    const wg = workgroup('aws_s3_bucket.results');
    const result = runOn(wg, [wg, resultsBucket, logsBucket, tlsPolicy('aws_s3_bucket.logs')]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
  });

  // Opposite outcome: only the bucket the policy is attached to changes.
  // The compliant case's primary behavior belongs to the pass requirement.
  it('does not flag when the same Deny policy is attached to the workgroup result bucket', () => {
    const wg = workgroup('aws_s3_bucket.results');
    const result = runOn(wg, [wg, resultsBucket, logsBucket, tlsPolicy('aws_s3_bucket.results')]);

    expect(result).toBeNull();
  });
});
