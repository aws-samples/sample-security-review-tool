import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-07 [CFN]: Unresolvable logging configuration should not be flagged', () => {
  it('passes when LoggingConfiguration is an unresolved Fn::If intrinsic', () => {
    const template = {
      Conditions: {
        EnableLogging: { 'Fn::Equals': [{ Ref: 'EnvType' }, 'prod'] },
      },
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              'Fn::If': [
                'EnableLogging',
                { DestinationBucketName: 'SomeLogBucket' },
                { Ref: 'AWS::NoValue' },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const resource = (template.Resources as Record<string, any>).MyBucket;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyBucket',
    };

    const factory = new S3001CfnAdapterFactory();
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when LoggingConfiguration is an unresolved Fn::ImportValue intrinsic', () => {
    const template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              'Fn::ImportValue': 'SharedLoggingConfigExport',
            },
          },
        },
      },
    } as unknown as Template;

    const resource = (template.Resources as Record<string, any>).MyBucket;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyBucket',
    };

    const factory = new S3001CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
