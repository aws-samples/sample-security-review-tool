import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001CfnAdapterFactory();

function workGroup(encryptionConfiguration: Record<string, unknown>): Resource {
  return {
    Type: 'AWS::Athena::WorkGroup',
    Properties: {
      Name: 'analytics-workgroup',
      WorkGroupConfiguration: {
        ResultConfiguration: {
          OutputLocation: 's3://query-results-bucket/prefix/',
          EncryptionConfiguration: encryptionConfiguration,
        },
      },
    },
  } as unknown as Resource;
}

function run(resource: Resource) {
  const template = { Resources: { AthenaWorkGroup: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'AthenaWorkGroup',
  };
  const adapter = factory.bind(context) as Ath001Adapter;
  return ath001Control.run(adapter, context);
}

describe('ATH-001 REQ-03 (CloudFormation): SSE_S3 query result encryption without a KMS key', () => {
  // Primary behavior owned by ATH-001: SSE_S3 is a valid encryption option and needs no KmsKey.
  it('passes when EncryptionOption is SSE_S3 and no KmsKey property is present', () => {
    const result = run(workGroup({ EncryptionOption: 'SSE_S3' }));

    expect(result).toBeNull();
  });

  it('passes when EncryptionOption is SSE_S3 and KmsKey is explicitly absent via AWS::NoValue resolution', () => {
    // AWS::NoValue resolves to undefined during preprocessing, leaving the key unset.
    const result = run(workGroup({ EncryptionOption: 'SSE_S3', KmsKey: undefined }));

    expect(result).toBeNull();
  });

  // Opposite outcome: keep the fixture identical except for the encryption option value,
  // which is present but not one of the supported options.
  it('flags a workgroup whose present EncryptionOption is not a supported option', () => {
    const result = run(workGroup({ EncryptionOption: 'AES256' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('AthenaWorkGroup');
  });
});
