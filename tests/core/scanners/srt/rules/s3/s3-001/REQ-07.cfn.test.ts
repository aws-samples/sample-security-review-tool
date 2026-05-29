import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (CloudFormation):
 * When the LoggingConfiguration on an S3 bucket is governed entirely by an
 * unresolvable intrinsic (e.g. Fn::If on a runtime condition), whether logging
 * is enabled cannot be determined at analysis time. The rule must not flag,
 * because it cannot definitively assert non-compliance.
 */
describe('S3-001 REQ-07 (CFN): unresolvable logging configuration should pass', () => {
  const factory = new S3001CfnAdapterFactory();

  const buildContext = (template: Template, logicalId: string): CfnContext => {
    const resource = template.Resources![logicalId];
    return {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };
  };

  it('does not flag a bucket whose LoggingConfiguration is an Fn::If', () => {
    const template: Template = {
      Resources: {
        MaybeLoggedBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              'Fn::If': [
                'EnableLoggingCondition',
                { DestinationBucketName: 'some-log-bucket' },
                { Ref: 'AWS::NoValue' },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const context = buildContext(template, 'MaybeLoggedBucket');
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does not flag a bucket whose LoggingConfiguration is an Fn::ImportValue', () => {
    const template: Template = {
      Resources: {
        ImportedLoggingBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            LoggingConfiguration: {
              'Fn::ImportValue': 'SharedLoggingConfigExport',
            },
          },
        },
      },
    } as unknown as Template;

    const context = buildContext(template, 'ImportedLoggingBucket');
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
