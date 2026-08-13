import { describe, it, expect } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001CfnAdapterFactory();

function scan(resource: Resource, logicalId = 'AthenaWorkGroup') {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  return ath001Control.run(factory.bind(context), context);
}

describe('ATH-001 CloudFormation - query result encryption', () => {
  // REQ-01 (primary): workgroup with no configuration at all must be flagged.
  it('flags an Athena workgroup defined with no configuration settings at all', () => {
    const resource = {
      Type: 'AWS::Athena::WorkGroup',
      Properties: {
        Name: 'analytics-workgroup',
      },
    } as unknown as Resource;

    const result = scan(resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
    expect(result?.resourceName).toBe('AthenaWorkGroup');
  });

  // Opposite outcome: nearest input that flips the verdict — the same workgroup
  // with an explicit query result encryption option present.
  it('does not flag an Athena workgroup that specifies SSE_S3 query result encryption', () => {
    const resource = {
      Type: 'AWS::Athena::WorkGroup',
      Properties: {
        Name: 'analytics-workgroup',
        WorkGroupConfiguration: {
          ResultConfiguration: {
            EncryptionConfiguration: {
              EncryptionOption: 'SSE_S3',
            },
          },
        },
      },
    } as unknown as Resource;

    const result = scan(resource);

    expect(result).toBeNull();
  });
});
