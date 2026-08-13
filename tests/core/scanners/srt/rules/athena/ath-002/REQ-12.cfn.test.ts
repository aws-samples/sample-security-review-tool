import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002CfnAdapterFactory();
const BUCKET_NAME = 'athena-results-bucket';

/**
 * Bucket policy with several unrelated statements. `secureTransportValue` is the value
 * asserted for aws:SecureTransport in the Deny statement's Bool condition:
 *  - 'false' -> the Deny fires on non-TLS requests (qualifying TLS enforcement)
 *  - 'true'  -> the Deny fires only on TLS requests (does NOT enforce TLS)
 */
function policyDocument(secureTransportValue: string): Record<string, unknown> {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AllowAnalystRead',
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::123456789012:role/Analyst' },
        Action: ['s3:GetObject', 's3:ListBucket'],
        Resource: [`arn:aws:s3:::${BUCKET_NAME}`, `arn:aws:s3:::${BUCKET_NAME}/*`],
      },
      {
        Sid: 'DenyUnEncryptedTransport',
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:*',
        Resource: [`arn:aws:s3:::${BUCKET_NAME}`, `arn:aws:s3:::${BUCKET_NAME}/*`],
        Condition: { Bool: { 'aws:SecureTransport': secureTransportValue } },
      },
      {
        Sid: 'DenyIncorrectEncryptionHeader',
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:PutObject',
        Resource: `arn:aws:s3:::${BUCKET_NAME}/*`,
        Condition: { StringNotEquals: { 's3:x-amz-server-side-encryption': 'aws:kms' } },
      },
    ],
  };
}

function template(secureTransportValue: string): Template {
  return {
    Resources: {
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: BUCKET_NAME },
      },
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          // !Ref ResultsBucket collapses to the logical id after preprocessing
          Bucket: 'ResultsBucket',
          PolicyDocument: policyDocument(secureTransportValue),
        },
      },
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: {
              OutputLocation: `s3://${BUCKET_NAME}/query-results/`,
            },
          },
        },
      },
    },
  } as unknown as Template;
}

function evaluateWorkGroup(secureTransportValue: string) {
  const tpl = template(secureTransportValue);
  const resources = tpl.Resources as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template: tpl,
    resource: resources['AnalyticsWorkGroup'],
    logicalId: 'AnalyticsWorkGroup',
  };
  return ath002Control.run(factory.bind(context), context);
}

describe('ATH-002 REQ-12 (CloudFormation): secure-transport Deny among unrelated statements', () => {
  // Primary behavior owned by this requirement.
  it('passes when the results bucket policy contains a qualifying secure-transport Deny alongside unrelated statements', () => {
    expect(evaluateWorkGroup('false')).toBeNull();
  });

  it('flags when the same multi-statement policy has no Deny that fires on non-TLS requests', () => {
    const result = evaluateWorkGroup('true');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
  });
});
