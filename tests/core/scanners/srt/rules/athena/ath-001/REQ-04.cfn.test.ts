import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001CfnAdapterFactory();

function buildContext(encryptionConfiguration: unknown): CfnContext {
  const resource = {
    Type: 'AWS::Athena::WorkGroup',
    Properties: {
      Name: 'analytics-workgroup',
      WorkGroupConfiguration: {
        ResultConfiguration: {
          OutputLocation: 's3://query-results-bucket/results/',
          EncryptionConfiguration: encryptionConfiguration,
        },
      },
    },
  } as unknown as Resource;

  const template = { Resources: { AnalyticsWorkGroup: resource } } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'AnalyticsWorkGroup',
  };
}

function run(encryptionConfiguration: unknown) {
  const context = buildContext(encryptionConfiguration);
  return ath001Control.run(factory.bind(context), context);
}

describe('ATH-001 CloudFormation — SSE_KMS with a KMS key specified', () => {
  // Primary behavior owned by this requirement: SSE_KMS + KmsKey satisfies the rule.
  it('passes when EncryptionOption is SSE_KMS and a KmsKey is provided', () => {
    const result = run({
      EncryptionOption: 'SSE_KMS',
      KmsKey: 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    });

    expect(result).toBeNull();
  });

  it('passes when EncryptionOption is SSE_KMS and the KmsKey is a resolved reference to a template key', () => {
    // !Ref AthenaKey / !GetAtt AthenaKey.Arn both resolve to the logical ID string.
    const result = run({ EncryptionOption: 'SSE_KMS', KmsKey: 'AthenaKey' });

    expect(result).toBeNull();
  });

  // Opposite outcome: same supported KMS-based option, but the required key is not specified.
  it('flags SSE_KMS when the KmsKey is present but empty, so no key is actually specified', () => {
    const result = run({ EncryptionOption: 'SSE_KMS', KmsKey: '' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
  });
});
