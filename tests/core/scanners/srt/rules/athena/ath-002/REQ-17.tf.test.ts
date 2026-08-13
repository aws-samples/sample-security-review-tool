import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-17 (ATH-002): When an Athena workgroup writes query results to an S3 bucket that is not
 * part of the assessed plan, its bucket policy is not resolvable, so the control must pass.
 */

const factory = new Ath002TfAdapterFactory();

function workGroup(outputLocation: string): TerraformResource {
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

function scan(resources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: resources[0],
    allResources: resources,
  };
  const adapter = factory.bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

describe('ATH-002 REQ-17 (Terraform): output bucket external to the plan', () => {
  it('passes when the query-results bucket is not defined anywhere in the assessed plan', () => {
    const result = scan([workGroup('s3://external-results-bucket/queries/')]);

    expect(result).toBeNull();
  });

  it('passes when no S3 bucket or bucket policy resources exist in the plan at all', () => {
    const result = scan([
      workGroup('s3://another-account-results-bucket/'),
      {
        type: 'aws_sns_topic',
        name: 'unrelated',
        address: 'aws_sns_topic.unrelated',
        values: { name: 'unrelated' },
      } as unknown as TerraformResource,
    ]);

    expect(result).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict is the SAME workgroup whose
  // results bucket IS in the plan (reference form, collapsed to the bucket address) with an
  // inspectable policy that fails to deny non-TLS requests. Primary ownership of this flagging
  // behaviour belongs to ATH-002's 'output-bucket-allows-insecure-transport' scenario.
  it('flags the workgroup when the referenced in-plan results bucket has a policy that does not enforce TLS', () => {
    const result = scan([
      workGroup('s3://internal-results-bucket/queries/'),
      {
        type: 'aws_s3_bucket',
        name: 'results',
        address: 'aws_s3_bucket.results',
        values: { bucket: 'internal-results-bucket' },
      } as unknown as TerraformResource,
      {
        type: 'aws_s3_bucket_policy',
        name: 'results',
        address: 'aws_s3_bucket_policy.results',
        values: {
          // Reference form: bucket = aws_s3_bucket.results.id collapses to the address
          bucket: 'aws_s3_bucket.results',
          policy: JSON.stringify({
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: { AWS: 'arn:aws:iam::123456789012:root' },
                Action: 's3:GetObject',
                Resource: 'arn:aws:s3:::internal-results-bucket/*',
              },
            ],
          }),
        },
      } as unknown as TerraformResource,
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });
});
