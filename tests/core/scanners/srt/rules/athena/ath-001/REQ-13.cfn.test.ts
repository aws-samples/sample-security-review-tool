import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001CfnAdapterFactory();

function scan(resource: Resource) {
  const template = { Resources: { WorkGroup: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'WorkGroup',
  };
  const adapter = factory.bind(context) as Ath001Adapter;
  return ath001Control.run(adapter, context);
}

describe('ATH-001 (CloudFormation) - customer content encryption is not query result encryption', () => {
  // REQ-13 owns this behavior: customer-managed key for Athena-managed customer
  // content / notebook data does NOT satisfy query result encryption.
  it('flags a workgroup that sets CustomerContentEncryptionConfiguration but no query result encryption', () => {
    const result = scan({
      Type: 'AWS::Athena::WorkGroup',
      Properties: {
        Name: 'analytics',
        WorkGroupConfiguration: {
          CustomerContentEncryptionConfiguration: {
            KmsKey: 'arn:aws:kms:us-east-1:123456789012:key/abc-123',
          },
          ResultConfiguration: {
            OutputLocation: 's3://my-athena-results/',
          },
        },
      },
    } as unknown as Resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
    expect(result?.resourceName).toBe('WorkGroup');
  });

  // Opposite outcome: identical fixture except query result encryption IS specified.
  it('does not flag when the same workgroup also specifies query result encryption', () => {
    const result = scan({
      Type: 'AWS::Athena::WorkGroup',
      Properties: {
        Name: 'analytics',
        WorkGroupConfiguration: {
          CustomerContentEncryptionConfiguration: {
            KmsKey: 'arn:aws:kms:us-east-1:123456789012:key/abc-123',
          },
          ResultConfiguration: {
            OutputLocation: 's3://my-athena-results/',
            EncryptionConfiguration: {
              EncryptionOption: 'SSE_S3',
            },
          },
        },
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });
});
