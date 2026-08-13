import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (ATH-002): The Deny statement on the Athena results bucket must enforce TLS for
 * ALL requests. A Deny scoped to a single narrow operation (e.g. only object reads) leaves
 * other plaintext operations possible, so the workgroup must still be flagged.
 */

const OUTPUT_LOCATION = 's3://athena-results/query/';
const BUCKET_NAME = 'athena-results';

function bucketPolicyStatement(action: unknown, resource: unknown): Record<string, unknown> {
  return {
    Sid: 'DenyInsecureTransport',
    Effect: 'Deny',
    Principal: '*',
    Action: action,
    Resource: resource,
    Condition: { Bool: { 'aws:SecureTransport': 'false' } },
  };
}

function buildTemplate(policyStatement: Record<string, unknown>, policyBucket: string): Template {
  return {
    Resources: {
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: { OutputLocation: OUTPUT_LOCATION },
          },
        },
      },
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: BUCKET_NAME },
      },
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          // !Ref ResultsBucket resolves to the logical ID string after preprocessing
          Bucket: policyBucket,
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [policyStatement],
          },
        },
      },
    },
  } as unknown as Template;
}

function runOnWorkGroup(template: Template): ScanResult | null {
  const resources = (template.Resources ?? {}) as Record<string, Resource>;
  const resource = resources['AnalyticsWorkGroup'];
  const context: CfnContext = {
    stackName: 'analytics-stack',
    template,
    resource,
    logicalId: 'AnalyticsWorkGroup',
  };
  const adapter = new Ath002CfnAdapterFactory().bind(context);
  return ath002Control.run(adapter, context);
}

describe('ATH-002 REQ-07 (CloudFormation): TLS Deny must cover all requests', () => {
  it('flags a workgroup whose results bucket policy denies insecure transport for only s3:GetObject (reference form)', () => {
    const template = buildTemplate(
      bucketPolicyStatement('s3:GetObject', `arn:aws:s3:::${BUCKET_NAME}/*`),
      'ResultsBucket',
    );

    const result = runOnWorkGroup(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
  });

  it('flags a workgroup whose results bucket policy denies insecure transport for only a narrow write operation (literal bucket name form)', () => {
    const template = buildTemplate(
      bucketPolicyStatement(['s3:PutObject'], `arn:aws:s3:::${BUCKET_NAME}/*`),
      BUCKET_NAME,
    );

    const result = runOnWorkGroup(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
  });

  // Opposite outcome: identical fixture except the Deny covers all actions on the whole bucket.
  it('does not flag a workgroup whose results bucket policy denies insecure transport for all requests', () => {
    const template = buildTemplate(
      bucketPolicyStatement('s3:*', [
        `arn:aws:s3:::${BUCKET_NAME}`,
        `arn:aws:s3:::${BUCKET_NAME}/*`,
      ]),
      'ResultsBucket',
    );

    const result = runOnWorkGroup(template);

    expect(result).toBeNull();
  });
});
