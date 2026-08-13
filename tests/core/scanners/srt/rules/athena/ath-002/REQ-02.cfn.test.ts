import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002CfnAdapterFactory();

const WORKGROUP_ID = 'AnalyticsWorkGroup';
const BUCKET_ID = 'ResultsBucket';
const BUCKET_NAME = 'athena-results-bucket';

function workGroup(): Resource {
  return {
    Type: 'AWS::Athena::WorkGroup',
    Properties: {
      Name: 'analytics',
      WorkGroupConfiguration: {
        ResultConfiguration: {
          // Post-preprocessing value of !Sub "s3://${ResultsBucket}/queries/" would be
          // "s3://ResultsBucket/queries/"; here the bucket name literal is used.
          OutputLocation: `s3://${BUCKET_NAME}/queries/`,
        },
      },
    },
  } as unknown as Resource;
}

function resultsBucket(): Resource {
  return {
    Type: 'AWS::S3::Bucket',
    Properties: { BucketName: BUCKET_NAME },
  } as unknown as Resource;
}

function tlsDenyBucketPolicy(): Resource {
  return {
    Type: 'AWS::S3::BucketPolicy',
    Properties: {
      Bucket: BUCKET_ID,
      PolicyDocument: {
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
      },
    },
  } as unknown as Resource;
}

function run(resources: Record<string, Resource>): ScanResult | null {
  const template = { Resources: resources } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[WORKGROUP_ID]!,
    logicalId: WORKGROUP_ID,
  };
  const adapter = factory.bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

describe('ATH-002 (CloudFormation) - results bucket with no access policy of any kind', () => {
  // Primary behavior owned by this requirement: the output bucket exists in the
  // template but has no bucket policy at all, so nothing denies plaintext HTTP.
  it('flags a workgroup whose results bucket has no bucket policy', () => {
    const result = run({
      [WORKGROUP_ID]: workGroup(),
      [BUCKET_ID]: resultsBucket(),
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe(WORKGROUP_ID);
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
  });

  it('flags when the results bucket is referenced by logical id and has no bucket policy', () => {
    const wg = workGroup() as unknown as { Properties: Record<string, any> };
    wg.Properties['WorkGroupConfiguration'].ResultConfiguration.OutputLocation = `s3://${BUCKET_ID}/queries/`;

    const result = run({
      [WORKGROUP_ID]: wg as unknown as Resource,
      [BUCKET_ID]: resultsBucket(),
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
  });

  // Opposite outcome: identical template except the results bucket IS governed by a
  // bucket policy denying requests where aws:SecureTransport is false.
  it('does not flag when the results bucket has a policy denying non-TLS requests', () => {
    const result = run({
      [WORKGROUP_ID]: workGroup(),
      [BUCKET_ID]: resultsBucket(),
      ResultsBucketPolicy: tlsDenyBucketPolicy(),
    });

    expect(result).toBeNull();
  });
});
