import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (ATH-001): a KMS-based encryption option satisfied by a broad or indirect
 * key identifier (alias, key id, or an in-template reference that preprocessing
 * collapses to a logical id) must PASS. The rule does not validate key format.
 */

const factory = new Ath001CfnAdapterFactory();

function buildTemplate(encryption: unknown): Template {
  return {
    Resources: {
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: {
              EncryptionConfiguration: encryption,
            },
          },
        },
      },
    },
  } as unknown as Template;
}

function run(encryption: unknown): ScanResult | null {
  const template = buildTemplate(encryption);
  const resource = (template.Resources as Record<string, Resource>)['AnalyticsWorkGroup'] as Resource;
  const context: CfnContext = {
    stackName: 'analytics-stack',
    template,
    resource,
    logicalId: 'AnalyticsWorkGroup',
  };
  const adapter = factory.bind(context) as Ath001Adapter;
  return ath001Control.run(adapter, context);
}

describe('ATH-001 REQ-09 (CloudFormation): KMS key supplied as a broad or indirect identifier', () => {
  it('passes when SSE_KMS uses a KMS alias instead of a key ARN', () => {
    expect(run({ EncryptionOption: 'SSE_KMS', KmsKey: 'alias/athena-results' })).toBeNull();
  });

  it('passes when CSE_KMS uses a bare KMS key id instead of a key ARN', () => {
    expect(run({ EncryptionOption: 'CSE_KMS', KmsKey: '1234abcd-12ab-34cd-56ef-1234567890ab' })).toBeNull();
  });

  it('passes when SSE_KMS references a key defined elsewhere in the template (Ref collapses to the logical id)', () => {
    // !Ref ResultsKey / !GetAtt ResultsKey.Arn both preprocess to the string "ResultsKey".
    expect(run({ EncryptionOption: 'SSE_KMS', KmsKey: 'ResultsKey' })).toBeNull();
  });

  // Opposite outcome: same KMS-based option, but the key identifier is present yet empty,
  // so no key is actually specified. Primary behavior owned by the missing-kms-key requirement.
  it('flags when SSE_KMS supplies an empty key identifier', () => {
    const result = run({ EncryptionOption: 'SSE_KMS', KmsKey: '   ' });
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
  });
});
