import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-15 (ATH-002): An Athena workgroup's results bucket policy that only grants
 * access CONDITIONED on aws:SecureTransport (a conditional Allow) — with no Deny
 * statement for requests lacking secure transport — must still be flagged.
 * Only an explicit Deny guarantees plaintext access is blocked.
 */

const CONDITIONAL_ALLOW_ONLY = {
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'AllowOnlyOverTls',
      Effect: 'Allow',
      Principal: { AWS: 'arn:aws:iam::123456789012:root' },
      Action: 's3:*',
      Resource: ['arn:aws:s3:::athena-results', 'arn:aws:s3:::athena-results/*'],
      Condition: { Bool: { 'aws:SecureTransport': 'true' } },
    },
  ],
};

const EXPLICIT_DENY_INSECURE = {
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'DenyInsecureTransport',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: ['arn:aws:s3:::athena-results', 'arn:aws:s3:::athena-results/*'],
      Condition: { Bool: { 'aws:SecureTransport': 'false' } },
    },
  ],
};

// Values shown as they appear AFTER parseCfnTemplate preprocessing:
// `!Ref ResultsBucket` on the BucketPolicy collapses to the logical id string.
function buildTemplate(policyDocument: unknown): Template {
  return {
    Resources: {
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: {
              OutputLocation: 's3://athena-results/query-output/',
            },
          },
        },
      },
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: 'athena-results' },
      },
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          Bucket: 'ResultsBucket',
          PolicyDocument: policyDocument,
        },
      },
    },
  } as unknown as Template;
}

function run(policyDocument: unknown) {
  const template = buildTemplate(policyDocument);
  const resources = template.Resources as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['AnalyticsWorkGroup'],
    logicalId: 'AnalyticsWorkGroup',
  };
  const adapter = new Ath002CfnAdapterFactory().bind(context);
  return ath002Control.run(adapter, context);
}

describe('ATH-002 REQ-15 (CloudFormation)', () => {
  it('flags a workgroup whose results bucket policy only conditions an Allow on aws:SecureTransport', () => {
    const result = run(CONDITIONAL_ALLOW_ONLY);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
  });

  // Opposite outcome: identical fixture except the statement is an explicit Deny
  // on requests lacking secure transport — the form the requirement demands.
  it('does not flag when the same bucket policy denies requests without secure transport', () => {
    expect(run(EXPLICIT_DENY_INSECURE)).toBeNull();
  });
});
