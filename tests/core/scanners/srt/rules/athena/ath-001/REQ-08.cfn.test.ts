import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001CfnAdapterFactory();

function buildTemplate(encryptionOption: string, kmsKey: unknown): Template {
  const properties: Record<string, unknown> = {
    Name: 'analytics-workgroup',
    WorkGroupConfiguration: {
      ResultConfiguration: {
        EncryptionConfiguration: {
          EncryptionOption: encryptionOption,
          ...(kmsKey === undefined ? {} : { KmsKey: kmsKey }),
        },
      },
    },
  };

  return {
    Resources: {
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: properties,
      } as unknown as Resource,
    },
  } as Template;
}

function scan(encryptionOption: string, kmsKey: unknown) {
  const template = buildTemplate(encryptionOption, kmsKey);
  const resource = (template.Resources as Record<string, Resource>)['AnalyticsWorkGroup'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'AnalyticsWorkGroup',
  };
  return ath001Control.run(factory.bind(context), context);
}

describe('ATH-001 CloudFormation — KMS-based encryption with a blank key identifier', () => {
  // Primary behavior owned by this requirement: an empty or whitespace-only
  // KmsKey does not identify a key, so it must be flagged.
  it('flags SSE_KMS with an empty string KmsKey', () => {
    const result = scan('SSE_KMS', '');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
  });

  it('flags SSE_KMS with a whitespace-only KmsKey', () => {
    const result = scan('SSE_KMS', '   ');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
  });

  it('flags CSE_KMS with a whitespace-only KmsKey (tabs and newlines)', () => {
    const result = scan('CSE_KMS', '\t\n ');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
  });

  // Opposite outcome: nearest input that flips the verdict — the same KMS-based
  // option with a real, non-blank key identifier present.
  it('does not flag SSE_KMS when the KmsKey is a non-blank identifier', () => {
    const result = scan('SSE_KMS', 'arn:aws:kms:us-east-1:123456789012:key/abcd-1234');
    expect(result).toBeNull();
  });
});
