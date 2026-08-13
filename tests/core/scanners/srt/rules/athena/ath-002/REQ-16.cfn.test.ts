import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.cfn.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002CfnAdapterFactory();

function scanWorkGroup(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources ?? {})[logicalId]!;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter = factory.bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

/**
 * Builds a workgroup that relies on Athena managed query result storage.
 * `managedEnabled` is the only thing that varies between the primary and opposite cases.
 */
function templateWithManagedStorage(managedEnabled: boolean): Template {
  return {
    Resources: {
      AnalyticsWorkGroup: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics-workgroup',
          WorkGroupConfiguration: {
            EnforceWorkGroupConfiguration: true,
            ManagedQueryResultsConfiguration: {
              Enabled: managedEnabled,
            },
          },
        },
      },
    },
  } as unknown as Template;
}

describe('ATH-002 REQ-16 (CloudFormation): managed query results storage', () => {
  // Primary behavior owned by this requirement: managed storage means there is no
  // customer output bucket, so no bucket-policy finding applies.
  it('passes a workgroup that uses Athena managed query results storage instead of a customer bucket', () => {
    const result = scanWorkGroup(templateWithManagedStorage(true), 'AnalyticsWorkGroup');

    expect(result).toBeNull();
  });

  // Opposite outcome: identical workgroup except managed storage is switched off,
  // leaving no query-result location at all (ATH-002 missing-output-location).
  it('flags an otherwise identical workgroup whose managed query results storage is disabled', () => {
    const result = scanWorkGroup(templateWithManagedStorage(false), 'AnalyticsWorkGroup');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('AnalyticsWorkGroup');
  });
});
