import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001CfnAdapterFactory();

function scan(resource: Resource): ReturnType<typeof ath001Control.run> {
  const template: Template = { Resources: { AnalyticsWorkGroup: resource } };
  const context: CfnContext = {
    stackName: 'analytics-stack',
    template,
    resource,
    logicalId: 'AnalyticsWorkGroup',
  };
  return ath001Control.run(factory.bind(context), context);
}

function workGroup(properties: Record<string, unknown>): Resource {
  return {
    Type: 'AWS::Athena::WorkGroup',
    Properties: { Name: 'analytics', ...properties },
  } as unknown as Resource;
}

describe('ATH-001 (CloudFormation) - result settings that explicitly remove or clear query result encryption', () => {
  // REQ-12 owns this behavior: clearing the encryption configuration must be flagged.
  it('flags a workgroup whose result configuration updates explicitly remove the encryption configuration', () => {
    const result = scan(
      workGroup({
        WorkGroupConfiguration: {
          ResultConfiguration: {
            OutputLocation: 's3://analytics-results/',
          },
        },
        WorkGroupConfigurationUpdates: {
          ResultConfigurationUpdates: {
            OutputLocation: 's3://analytics-results/',
            RemoveEncryptionConfiguration: true,
          },
        },
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
  });

  // REQ-12: an emptied-out EncryptionConfiguration block leaves no enforced encryption.
  it('flags a workgroup whose EncryptionConfiguration block has been cleared to an empty object', () => {
    const result = scan(
      workGroup({
        WorkGroupConfiguration: {
          ResultConfiguration: {
            OutputLocation: 's3://analytics-results/',
            EncryptionConfiguration: {},
          },
        },
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
  });

  // Opposite outcome: identical fixture except the encryption configuration is retained.
  it('does not flag a workgroup whose result configuration retains SSE_S3 query result encryption', () => {
    const result = scan(
      workGroup({
        WorkGroupConfiguration: {
          ResultConfiguration: {
            OutputLocation: 's3://analytics-results/',
            EncryptionConfiguration: { EncryptionOption: 'SSE_S3' },
          },
        },
        WorkGroupConfigurationUpdates: {
          ResultConfigurationUpdates: {
            OutputLocation: 's3://analytics-results/',
            EncryptionConfiguration: { EncryptionOption: 'SSE_S3' },
          },
        },
      }),
    );

    expect(result).toBeNull();
  });
});
