import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-04 (CloudFormation): bucket has lifecycle configuration with both enabled and disabled rules', () => {
  it('passes when at least one rule is enabled even if other rules are disabled', () => {
    const logicalId = 'MyBucket';
    const resource = {
      Type: 'AWS::S3::Bucket',
      Properties: {
        LifecycleConfiguration: {
          Rules: [
            {
              Id: 'EnabledRule',
              Status: 'Enabled',
              ExpirationInDays: 365,
            },
            {
              Id: 'DisabledRule',
              Status: 'Disabled',
              ExpirationInDays: 30,
            },
          ],
        },
      },
    };

    const template = {
      Resources: {
        [logicalId]: resource,
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template: template as unknown as CfnContext['template'],
      resource: resource as unknown as CfnContext['resource'],
      logicalId,
    };

    const factory = new S3008CfnAdapterFactory();
    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
