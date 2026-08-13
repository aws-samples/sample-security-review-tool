import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001CfnAdapterFactory();

function buildContext(resource: Resource): CfnContext {
  const template = { Resources: { WorkGroup: resource } } as unknown as Template;
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'WorkGroup',
  };
}

function workGroup(encryptionConfiguration: Record<string, unknown>): Resource {
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

function run(resource: Resource) {
  const context = buildContext(resource);
  const adapter = factory.bind(context) as Ath001Adapter;
  return ath001Control.run(adapter, context);
}

describe('ATH-001 CloudFormation - empty query result encryption settings', () => {
  // Primary behavior owned by this requirement: an EncryptionConfiguration
  // container with no encryption option inside provides no encryption.
  it('flags a workgroup whose EncryptionConfiguration is an empty structure', () => {
    const result = run(workGroup({}));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
    expect(result?.resourceName).toBe('WorkGroup');
  });

  // Opposite outcome: nearest input that flips the verdict - the same
  // EncryptionConfiguration structure, populated with a supported option.
  it('does not flag a workgroup whose EncryptionConfiguration specifies SSE_S3', () => {
    const result = run(workGroup({ EncryptionOption: 'SSE_S3' }));

    expect(result).toBeNull();
  });
});
