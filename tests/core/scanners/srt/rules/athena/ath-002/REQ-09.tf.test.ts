import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET_NAME = 'athena-results-bucket';
const OUTPUT_LOCATION = `s3://${BUCKET_NAME}/query-results/`;
const INSECURE_TRANSPORT_SCENARIO = 'output-bucket-allows-insecure-transport';

const factory = new Ath002TfAdapterFactory();

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
    configuration: [{ result_configuration: [{ output_location: OUTPUT_LOCATION }] }],
  },
} as unknown as TerraformResource;

/** bucketRef: 'aws_s3_bucket.results' (reference form) or the literal bucket name. */
function bucketPolicy(policyDocument: unknown, bucketRef: string): TerraformResource {
  return {
    type: 'aws_s3_bucket_policy',
    name: 'results',
    address: 'aws_s3_bucket_policy.results',
    values: { bucket: bucketRef, policy: JSON.stringify(policyDocument) },
  } as unknown as TerraformResource;
}

function runWorkGroup(policyDocument: unknown, bucketRef = 'aws_s3_bucket.results'): ScanResult | null {
  const allResources = [workgroup, bucket, bucketPolicy(policyDocument, bucketRef)];
  const context: TfContext = { projectName: 'analytics-project', resource: workgroup, allResources };
  const adapter = factory.bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

describe('ATH-002 REQ-09 (Terraform): secure-transport Deny must apply to all requests', () => {
  it('flags a workgroup whose results bucket policy excludes principals from the secure-transport Deny via NotPrincipal', () => {
    const result = runWorkGroup({
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'DenyInsecureTransportExceptPipeline',
          Effect: 'Deny',
          NotPrincipal: { AWS: 'arn:aws:iam::123456789012:role/LegacyEtlRole' },
          Action: 's3:*',
          Resource: [`arn:aws:s3:::${BUCKET_NAME}`, `arn:aws:s3:::${BUCKET_NAME}/*`],
          Condition: { Bool: { 'aws:SecureTransport': 'false' } },
        },
      ],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
    expect(result?.fix).toContain(
      ath002Control.remediationScenarios.find(s => s.scenario === INSECURE_TRANSPORT_SCENARIO)?.intent,
    );
  });

  it('flags a workgroup whose results bucket policy carves identities out of the Deny with a principal condition (literal bucket name form)', () => {
    const result = runWorkGroup(
      {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'DenyInsecureTransportUnlessLegacyCaller',
            Effect: 'Deny',
            Principal: '*',
            Action: 's3:*',
            Resource: [`arn:aws:s3:::${BUCKET_NAME}`, `arn:aws:s3:::${BUCKET_NAME}/*`],
            Condition: {
              Bool: { 'aws:SecureTransport': 'false' },
              StringNotEquals: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/LegacyEtlRole' },
            },
          },
        ],
      },
      BUCKET_NAME,
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
  });

  // Opposite outcome: identical policy with the carve-out removed so the Deny reaches every
  // principal. The compliant-policy behavior itself belongs to the base ATH-002 requirement.
  it('does not flag when the secure-transport Deny applies to all principals with no exclusion', () => {
    const result = runWorkGroup({
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
    });

    expect(result).toBeNull();
  });
});
