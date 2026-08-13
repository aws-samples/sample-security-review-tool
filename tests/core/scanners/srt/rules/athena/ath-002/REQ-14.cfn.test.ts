import { describe, it, expect } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002CfnAdapterFactory();

function buildTemplate(policyStatement: unknown): Template {
  return {
    Resources: {
      ResultsBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: 'my-results-bucket' },
      },
      ResultsBucketPolicy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          // !Ref ResultsBucket resolves to the logical id string
          Bucket: 'ResultsBucket',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [policyStatement],
          },
        },
      },
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: {
              OutputLocation: 's3://my-results-bucket/results/',
            },
          },
        },
      },
    },
  } as unknown as Template;
}

function runOnWorkGroup(template: Template) {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['AnalyticsWorkGroup'],
    logicalId: 'AnalyticsWorkGroup',
  };
  return ath002Control.run(factory.bind(context), context);
}

// Primary behavior for REQ-14 (ATH-002): a broad conditional Deny whose condition
// constrains something other than transport security is not TLS enforcement.
describe('ATH-002 REQ-14 (CloudFormation): Deny conditioned on a non-transport attribute', () => {
  it('flags a workgroup whose results bucket policy denies based on aws:SourceIp instead of aws:SecureTransport', () => {
    const template = buildTemplate({
      Sid: 'DenyOutsideNetwork',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: ['arn:aws:s3:::my-results-bucket', 'arn:aws:s3:::my-results-bucket/*'],
      Condition: {
        NotIpAddress: { 'aws:SourceIp': '203.0.113.0/24' },
      },
    });

    const result = runOnWorkGroup(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
  });

  // Opposite outcome: identical broad Deny, but the condition keys on transport security.
  it('does not flag when the same broad Deny is conditioned on aws:SecureTransport', () => {
    const template = buildTemplate({
      Sid: 'DenyInsecureTransport',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: ['arn:aws:s3:::my-results-bucket', 'arn:aws:s3:::my-results-bucket/*'],
      Condition: {
        Bool: { 'aws:SecureTransport': 'false' },
      },
    });

    const result = runOnWorkGroup(template);

    expect(result).toBeNull();
  });
});
