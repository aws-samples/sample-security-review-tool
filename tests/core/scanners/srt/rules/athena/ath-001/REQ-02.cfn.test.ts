import { describe, it, expect } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
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

function run(resource: Resource) {
  const context = buildContext(resource);
  return ath001Control.run(factory.bind(context), context);
}

describe('ATH-001 (CFN) - query result encryption required', () => {
  // Primary behavior owned by ATH-001: output location without encryption settings must be flagged.
  it('flags a workgroup with configuration and an output location but no query result encryption settings', () => {
    const resource = {
      Type: 'AWS::Athena::WorkGroup',
      Properties: {
        Name: 'analytics-workgroup',
        WorkGroupConfiguration: {
          EnforceWorkGroupConfiguration: true,
          PublishCloudWatchMetricsEnabled: true,
          ResultConfiguration: {
            OutputLocation: 's3://athena-results-bucket/queries/',
          },
        },
      },
    } as unknown as Resource;

    const result = run(resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
    expect(result?.resourceName).toBe('WorkGroup');
  });

  // Opposite outcome: identical fixture except query result encryption is configured.
  it('does not flag the same workgroup when query result encryption is configured with SSE_S3', () => {
    const resource = {
      Type: 'AWS::Athena::WorkGroup',
      Properties: {
        Name: 'analytics-workgroup',
        WorkGroupConfiguration: {
          EnforceWorkGroupConfiguration: true,
          PublishCloudWatchMetricsEnabled: true,
          ResultConfiguration: {
            OutputLocation: 's3://athena-results-bucket/queries/',
            EncryptionConfiguration: {
              EncryptionOption: 'SSE_S3',
            },
          },
        },
      },
    } as unknown as Resource;

    expect(run(resource)).toBeNull();
  });
});
