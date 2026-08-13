import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AnalyticsWorkGroup';

function scan(resource: Resource): ScanResult | null {
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
  const adapter = new Ath001CfnAdapterFactory().bind(context) as Ath001Adapter;
  return ath001Control.run(adapter, context);
}

function workGroup(encryptionConfiguration: unknown): Resource {
  return {
    Type: 'AWS::Athena::WorkGroup',
    Properties: {
      Name: 'analytics',
      WorkGroupConfiguration: {
        ResultConfiguration: {
          OutputLocation: 's3://query-results/',
          EncryptionConfiguration: encryptionConfiguration,
        },
      },
    },
  } as unknown as Resource;
}

describe('ATH-001 REQ-15 (CloudFormation): unresolvable query result encryption values', () => {
  // Primary behavior owned by this requirement: unresolvable values must not be flagged.
  it('passes when the encryption option is an unresolved Fn::If', () => {
    const result = scan(workGroup({
      EncryptionOption: { 'Fn::If': ['UseKms', 'SSE_KMS', 'SSE_S3'] },
    }));

    expect(result).toBeNull();
  });

  it('passes when the encryption option is an unresolved Fn::ImportValue', () => {
    const result = scan(workGroup({
      EncryptionOption: { 'Fn::ImportValue': 'SharedEncryptionOption' },
    }));

    expect(result).toBeNull();
  });

  it('passes when the whole encryption configuration block is an unresolved Fn::If', () => {
    const result = scan(workGroup({
      'Fn::If': [
        'UseEncryption',
        { EncryptionOption: 'SSE_S3' },
        { Ref: 'AWS::NoValue' },
      ],
    }));

    expect(result).toBeNull();
  });

  it('passes when a KMS-based option specifies a KMS key that is unresolvable at deployment time', () => {
    const result = scan(workGroup({
      EncryptionOption: 'SSE_KMS',
      KmsKey: { 'Fn::ImportValue': 'SharedQueryResultsKeyArn' },
    }));

    expect(result).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict — the encryption option is
  // statically resolvable and is not one of the supported options, so it must be flagged.
  // (Primary behavior for that case belongs to the supported-option requirement.)
  it('flags when the encryption option resolves to a statically known unsupported value', () => {
    const result = scan(workGroup({
      EncryptionOption: 'AES256',
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe(LOGICAL_ID);
  });
});
