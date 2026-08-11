import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (CloudFormation)
 * Scenario: Bucket policy allow statement grants access to a federated identity
 * provider (SAML/OIDC) identified by a specific provider ARN.
 * Expected: pass (no finding). A federated principal identified by a specific
 * provider ARN is an explicit, named trust relationship — analogous to naming
 * an IAM principal.
 */
describe('S3-002 REQ-09 [CloudFormation]: federated principal with specific provider ARN', () => {
  it('passes (no finding) for a SAML federated provider ARN on an AWS::S3::BucketPolicy', () => {
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        MyBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'MyBucket',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Federated: 'arn:aws:iam::123456789012:saml-provider/MySAMLProvider',
                  },
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const logicalId = 'MyBucketPolicy';
    const resource = template.Resources![logicalId]!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new S3002CfnAdapterFactory();
    expect(factory.appliesTo(resource.Type)).toBe(true);
    const adapter = factory.bind(context);

    const result = s3002Control.run(adapter, context);
    expect(result).toBeNull();
  });

  it('passes (no finding) for an OIDC federated provider ARN on an AWS::S3::BucketPolicy', () => {
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        MyBucketPolicy: {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'MyBucket',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Federated:
                      'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com',
                  },
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const logicalId = 'MyBucketPolicy';
    const resource = template.Resources![logicalId]!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new S3002CfnAdapterFactory();
    const adapter = factory.bind(context);

    const result = s3002Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
