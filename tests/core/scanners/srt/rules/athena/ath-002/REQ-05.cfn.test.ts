import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002CfnAdapterFactory();

const SECURE_TRANSPORT_DENY = {
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
};

/**
 * The workgroup writes results to ResultsBucket. A qualifying secure-transport Deny
 * policy exists in the template, but it is attached to LogsBucket instead.
 */
function buildTemplate(policyBucketLogicalId: string): Template {
  return {
    Resources: {
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: {
              // !Ref / !Sub would collapse to the logical id; a literal s3 uri is used here
              OutputLocation: 's3://wg-results-bucket/query-results/',
            },
          },
        },
      },
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: 'wg-results-bucket' },
      },
      LogsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: 'unrelated-logs-bucket' },
      },
      TlsPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          // after preprocessing !Ref LogsBucket becomes the logical id string
          Bucket: policyBucketLogicalId,
          PolicyDocument: SECURE_TRANSPORT_DENY,
        },
      },
    },
  } as unknown as Template;
}

function runOn(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources as Record<string, any>)[logicalId];
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

describe('ATH-002 CloudFormation - TLS Deny policy attached to a different bucket (REQ-05)', () => {
  it('flags the workgroup when the secure-transport Deny policy protects an unrelated bucket', () => {
    const result = runOn(buildTemplate('LogsBucket'), 'AnalyticsWorkGroup');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
  });

  // Opposite outcome: same template, the only change is which bucket the policy is
  // attached to. Primary behavior for the compliant case belongs to the pass requirement.
  it('does not flag when the same Deny policy is attached to the workgroup result bucket', () => {
    const result = runOn(buildTemplate('ResultsBucket'), 'AnalyticsWorkGroup');

    expect(result).toBeNull();
  });
});
