import { describe, it, expect } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001CfnAdapterFactory();

function buildContext(resource: Resource): CfnContext {
  const template = { Resources: { DisabledWorkGroup: resource } } as unknown as Template;
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'DisabledWorkGroup',
  };
}

function run(resource: Resource) {
  const context = buildContext(resource);
  const adapter = factory.bind(context) as Ath001Adapter;
  return ath001Control.run(adapter, context);
}

describe('ATH-001 REQ-17 (CloudFormation): workgroup state does not exempt the encryption requirement', () => {
  // Primary behavior owned by ATH-001: missing query result encryption must be flagged
  // even when the workgroup itself is DISABLED, since it can be re-enabled at any time.
  it('flags a DISABLED workgroup that has no query result encryption configuration', () => {
    const result = run({
      Type: 'AWS::Athena::WorkGroup',
      Properties: {
        Name: 'disabled-analytics',
        State: 'DISABLED',
        WorkGroupConfiguration: {
          ResultConfiguration: {
            OutputLocation: 's3://query-results-bucket/prefix/',
          },
        },
      },
    } as unknown as Resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('DisabledWorkGroup');
  });

  // Opposite outcome: identical DISABLED workgroup, only the encryption option is present.
  it('does not flag a DISABLED workgroup that has SSE_S3 query result encryption', () => {
    const result = run({
      Type: 'AWS::Athena::WorkGroup',
      Properties: {
        Name: 'disabled-analytics',
        State: 'DISABLED',
        WorkGroupConfiguration: {
          ResultConfiguration: {
            OutputLocation: 's3://query-results-bucket/prefix/',
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
