import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002TfAdapterFactory();

const BUCKET_ADDRESS = 'aws_s3_bucket.results';
const BUCKET_NAME = 'athena-results-bucket';

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

function resultsBucket(): TerraformResource {
  return {
    type: 'aws_s3_bucket',
    name: 'results',
    address: BUCKET_ADDRESS,
    values: { bucket: BUCKET_NAME },
  } as unknown as TerraformResource;
}

function tlsDenyBucketPolicy(): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: {
      bucket: BUCKET_ADDRESS,
      policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'DenyInsecureTransport',
            Effect: 'Deny',
            Principal: '*',
            Action: 's3:*',
            Resource: [`arn:aws:s3:::${BUCKET_NAME}`, `arn:aws:s3:::${BUCKET_NAME}/*`],
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
          },
        ],
      }),
    },
  } as unknown as TerraformResource;
}

function run(resources: TerraformResource[]): ScanResult | null {
  const workgroup = resources.find(resource => resource.type === 'aws_athena_workgroup')!;
  const context: TfContext = {
    projectName: 'test-project',
    resource: workgroup,
    allResources: resources,
  };
  const adapter = factory.bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

describe('ATH-002 (Terraform) - results bucket with no access policy of any kind', () => {
  // Primary behavior owned by this requirement: bucket exists in the plan, but no
  // aws_s3_bucket_policy is attached to it, so nothing denies plaintext HTTP.
  it('flags a workgroup whose results bucket (reference form) has no bucket policy', () => {
    const result = run([workGroup(BUCKET_ADDRESS), resultsBucket()]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
  });

  it('flags a workgroup whose results bucket (literal form) has no bucket policy', () => {
    const result = run([workGroup(`s3://${BUCKET_NAME}/queries/`), resultsBucket()]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
  });

  // Opposite outcome: identical plan except the results bucket IS governed by a
  // bucket policy denying requests where aws:SecureTransport is false.
  it('does not flag when the results bucket has a policy denying non-TLS requests', () => {
    const result = run([workGroup(BUCKET_ADDRESS), resultsBucket(), tlsDenyBucketPolicy()]);

    expect(result).toBeNull();
  });
});
