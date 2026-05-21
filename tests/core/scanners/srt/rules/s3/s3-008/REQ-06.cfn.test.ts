import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-06 CloudFormation: narrowly scoped enabled lifecycle rule passes', () => {
  it('passes when bucket has an enabled lifecycle rule scoped by a Prefix filter', () => {
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LifecycleConfiguration: {
              Rules: [
                {
                  Id: 'archive-logs',
                  Status: 'Enabled',
                  Prefix: 'logs/',
                  ExpirationInDays: 365,
                },
              ],
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyBucket,
      logicalId: 'MyBucket',
    };

    const factory = new S3008CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when bucket has an enabled lifecycle rule scoped by a Tag filter', () => {
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LifecycleConfiguration: {
              Rules: [
                {
                  Id: 'archive-tagged',
                  Status: 'Enabled',
                  TagFilters: [{ Key: 'archive', Value: 'true' }],
                  ExpirationInDays: 90,
                },
              ],
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyBucket,
      logicalId: 'MyBucket',
    };

    const factory = new S3008CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when bucket has an enabled lifecycle rule scoped by an object-size filter', () => {
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LifecycleConfiguration: {
              Rules: [
                {
                  Id: 'large-objects',
                  Status: 'Enabled',
                  ObjectSizeGreaterThan: 1048576,
                  ExpirationInDays: 30,
                },
              ],
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyBucket,
      logicalId: 'MyBucket',
    };

    const factory = new S3008CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
