import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (ATH-002): When the Athena workgroup's query-result output location cannot be
 * resolved at plan time (the plan reader records it as null because it derives from an
 * unresolvable / multi-source expression), the rule must NOT report a finding.
 */

const factory = new Ath002TfAdapterFactory();

const NON_TLS_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'AllowReads',
      Effect: 'Allow',
      Principal: { AWS: 'arn:aws:iam::123456789012:root' },
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::athena-results/*',
    },
  ],
});

const resultsBucket: TerraformResource = {
  type: 'aws_s3_bucket',
  name: 'results',
  address: 'aws_s3_bucket.results',
  values: { bucket: 'athena-results' },
} as unknown as TerraformResource;

// Reference form — in HCL the policy was wired with aws_s3_bucket.results.id
const nonTlsBucketPolicy: TerraformResource = {
  type: 'aws_s3_bucket_policy',
  name: 'results',
  address: 'aws_s3_bucket_policy.results',
  values: { bucket: 'aws_s3_bucket.results', policy: NON_TLS_POLICY },
} as unknown as TerraformResource;

function workGroup(outputLocation: unknown): TerraformResource {
  return {
    type: 'aws_athena_workgroup',
    name: 'analytics',
    address: 'aws_athena_workgroup.analytics',
    values: {
      name: 'analytics',
      configuration: [
        {
          result_configuration: [{ output_location: outputLocation }],
        },
      ],
    },
  } as unknown as TerraformResource;
}

function run(wg: TerraformResource, others: TerraformResource[]): ScanResult | null {
  const allResources = [wg, ...others];
  const context: TfContext = {
    projectName: 'test-project',
    resource: wg,
    allResources,
  };
  const adapter = factory.bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

describe('ATH-002 Terraform — unresolvable query-result output location', () => {
  it('produces no finding when the output location is unknown at plan time (null)', () => {
    // e.g. output_location = "s3://${var.external_bucket}/${aws_s3_bucket.results.id}/out/"
    expect(run(workGroup(null), [resultsBucket, nonTlsBucketPolicy])).toBeNull();
  });

  it('produces no finding when the unknown output location coexists with a non-TLS bucket policy', () => {
    expect(run(workGroup(null), [nonTlsBucketPolicy])).toBeNull();
  });

  // Opposite outcome — owned by the "output bucket allows insecure transport" requirement.
  // Only the resolvability of the output location changes: here it resolves to a literal
  // s3 URI for a bucket whose policy does not deny non-TLS requests, so a finding IS produced.
  it('reports a finding when the same output location resolves to a bucket lacking a TLS-enforcing policy', () => {
    const result = run(workGroup('s3://athena-results/queries/'), [resultsBucket, nonTlsBucketPolicy]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });
});
