import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'AWS::Athena::WorkGroup';
const LOGICAL_ID = 'AnalyticsWorkGroup';

function buildContext(encryptionConfiguration: Record<string, unknown>): CfnContext {
  const resource = {
    Type: RESOURCE_TYPE,
    Properties: {
      Name: 'analytics',
      WorkGroupConfiguration: {
        ResultConfiguration: {
          OutputLocation: 's3://analytics-results/queries/',
          EncryptionConfiguration: encryptionConfiguration,
        },
      },
    },
  } as unknown as Resource;

  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;

  return { stackName: 'analytics-stack', template, resource, logicalId: LOGICAL_ID };
}

function run(encryptionConfiguration: Record<string, unknown>) {
  const context = buildContext(encryptionConfiguration);
  const adapter = new Ath001CfnAdapterFactory().bind(context);
  return ath001Control.run(adapter, context);
}

describe('ATH-001 CloudFormation - SSE_KMS without a KMS key (REQ-05)', () => {
  it('flags a workgroup that selects SSE_KMS but supplies no KmsKey', () => {
    // Primary behavior owned by this requirement: KMS-based encryption requires a key.
    const result = run({ EncryptionOption: 'SSE_KMS' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.issue).toMatch(/KMS key/i);
  });

  it('flags a workgroup that selects SSE_KMS with an empty KmsKey value', () => {
    const result = run({ EncryptionOption: 'SSE_KMS', KmsKey: '' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.issue).toMatch(/KMS key/i);
  });

  it('does NOT flag the same workgroup once a KmsKey is supplied (opposite outcome)', () => {
    const result = run({
      EncryptionOption: 'SSE_KMS',
      KmsKey: 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    });

    expect(result).toBeNull();
  });
});
