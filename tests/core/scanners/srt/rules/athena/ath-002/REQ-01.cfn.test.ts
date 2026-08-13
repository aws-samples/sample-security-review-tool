import { describe, it, expect } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002CfnAdapterFactory();

function runOn(template: Template, logicalId: string) {
  const resource = (template.Resources as Record<string, any>)[logicalId];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  return ath002Control.run(factory.bind(context), context);
}

const secureTransportDenyPolicy = {
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'DenyInsecureTransport',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: ['arn:aws:s3:::my-results-bucket', 'arn:aws:s3:::my-results-bucket/*'],
      Condition: { Bool: { 'aws:SecureTransport': 'false' } },
    },
  ],
};

describe('ATH-002 (CloudFormation) - workgroup with no query-result output location', () => {
  // REQ-01 owns this behavior: no output location => no result bucket can be
  // identified, so the results cannot be shown to be TLS-protected => flag.
  it('flags a workgroup whose ResultConfiguration omits OutputLocation', () => {
    const template: Template = {
      Resources: {
        ResultsBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'my-results-bucket' },
        },
        ResultsBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'ResultsBucket',
            PolicyDocument: secureTransportDenyPolicy,
          },
        },
        WorkGroup: {
          Type: 'AWS::Athena::WorkGroup',
          Properties: {
            Name: 'analytics',
            WorkGroupConfiguration: {
              EnforceWorkGroupConfiguration: true,
              ResultConfiguration: {
                EncryptionConfiguration: { EncryptionOption: 'SSE_S3' },
              },
            },
          },
        },
      },
    } as unknown as Template;

    const result = runOn(template, 'WorkGroup');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('WorkGroup');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
  });

  it('flags a workgroup with no WorkGroupConfiguration at all', () => {
    const template: Template = {
      Resources: {
        WorkGroup: {
          Type: 'AWS::Athena::WorkGroup',
          Properties: { Name: 'analytics' },
        },
      },
    } as unknown as Template;

    expect(runOn(template, 'WorkGroup')).not.toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict - the same workgroup,
  // but with an OutputLocation pointing at a bucket whose policy denies non-TLS
  // requests. (Primary behavior for that case is owned by the TLS-policy requirement.)
  it('does not flag the same workgroup once an OutputLocation with a TLS-denying bucket policy is present', () => {
    const template: Template = {
      Resources: {
        ResultsBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'my-results-bucket' },
        },
        ResultsBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'ResultsBucket',
            PolicyDocument: secureTransportDenyPolicy,
          },
        },
        WorkGroup: {
          Type: 'AWS::Athena::WorkGroup',
          Properties: {
            Name: 'analytics',
            WorkGroupConfiguration: {
              EnforceWorkGroupConfiguration: true,
              ResultConfiguration: {
                OutputLocation: 's3://my-results-bucket/results/',
                EncryptionConfiguration: { EncryptionOption: 'SSE_S3' },
              },
            },
          },
        },
      },
    } as unknown as Template;

    expect(runOn(template, 'WorkGroup')).toBeNull();
  });
});
