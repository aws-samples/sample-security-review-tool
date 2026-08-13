import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001CfnAdapterFactory();

function buildWorkGroup(encryptionConfiguration: Record<string, unknown>): Resource {
  return {
    Type: 'AWS::Athena::WorkGroup',
    Properties: {
      Name: 'analytics',
      WorkGroupConfiguration: {
        ResultConfiguration: {
          OutputLocation: 's3://query-results-bucket/results/',
          EncryptionConfiguration: encryptionConfiguration,
        },
      },
    },
  } as unknown as Resource;
}

function run(resource: Resource) {
  const template = { Resources: { AnalyticsWorkGroup: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'AnalyticsWorkGroup',
  };
  return ath001Control.run(factory.bind(context), context);
}

describe('ATH-001 CloudFormation - CSE_KMS without a KMS key', () => {
  // Primary behavior owned by this requirement: CSE_KMS selected but no KmsKey specified.
  it('flags a workgroup using CSE_KMS with no KmsKey property', () => {
    const result = run(buildWorkGroup({ EncryptionOption: 'CSE_KMS' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
  });

  it('flags a workgroup using CSE_KMS with an empty KmsKey value', () => {
    const result = run(buildWorkGroup({ EncryptionOption: 'CSE_KMS', KmsKey: '' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
  });

  // Opposite outcome: identical fixture except the required KMS key is present.
  it('does not flag a workgroup using CSE_KMS when a KmsKey is provided', () => {
    const result = run(buildWorkGroup({
      EncryptionOption: 'CSE_KMS',
      KmsKey: 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    }));

    expect(result).toBeNull();
  });
});
