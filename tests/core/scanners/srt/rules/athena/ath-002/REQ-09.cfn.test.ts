import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET_NAME = 'athena-results-bucket';
const OUTPUT_LOCATION = `s3://${BUCKET_NAME}/query-results/`;
const INSECURE_TRANSPORT_FINDING = 'output-bucket-allows-insecure-transport';

const factory = new Ath002CfnAdapterFactory();

function template(policyDocument: unknown): Template {
  return {
    Resources: {
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: BUCKET_NAME },
      },
      // Bucket property written as !Ref ResultsBucket, which preprocessing collapses
      // to the logical id string "ResultsBucket".
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: { Bucket: 'ResultsBucket', PolicyDocument: policyDocument },
      },
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: { OutputLocation: OUTPUT_LOCATION },
          },
        },
      },
    },
  } as unknown as Template;
}

function runWorkGroup(policyDocument: unknown): ScanResult | null {
  const tpl = template(policyDocument);
  const resource = (tpl.Resources as Record<string, never>)['AnalyticsWorkGroup'];
  const context: CfnContext = {
    stackName: 'analytics-stack',
    template: tpl,
    resource,
    logicalId: 'AnalyticsWorkGroup',
  };
  const adapter = factory.bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

describe('ATH-002 REQ-09 (CloudFormation): secure-transport Deny must apply to all requests', () => {
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
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
    expect(result?.fix).toContain(ath002Control.findings[INSECURE_TRANSPORT_FINDING].remediation);
  });

  it('flags a workgroup whose results bucket policy carves identities out of the Deny with a principal condition', () => {
    const result = runWorkGroup({
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
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
  });

  // Opposite outcome: the nearest input that flips the verdict — identical policy with the
  // carve-out removed so the Deny applies to every principal. Primary behavior (a Deny that
  // does cover all requests passes) is owned by the base ATH-002 compliant requirement.
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
