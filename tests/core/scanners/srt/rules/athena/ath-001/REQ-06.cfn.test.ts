import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AnalyticsWorkGroup';

function buildTemplate(encryptionConfiguration: unknown): Template {
  return {
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::Athena::WorkGroup',
        Properties: {
          Name: 'analytics',
          WorkGroupConfiguration: {
            ResultConfiguration: {
              OutputLocation: 's3://query-results-bucket/results/',
              EncryptionConfiguration: encryptionConfiguration,
            },
          },
        },
      } as unknown as Resource,
    },
  } as unknown as Template;
}

function buildContext(encryptionConfiguration: unknown): CfnContext {
  const template = buildTemplate(encryptionConfiguration);
  return {
    stackName: 'analytics-stack',
    template,
    resource: template.Resources![LOGICAL_ID],
    logicalId: LOGICAL_ID,
  };
}

function bind(encryptionConfiguration: unknown): { adapter: Ath001Adapter; context: CfnContext } {
  const context = buildContext(encryptionConfiguration);
  const adapter = new Ath001CfnAdapterFactory().bind(context) as Ath001Adapter;
  return { adapter, context };
}

describe('ATH-001 CloudFormation - CSE_KMS with a KMS key', () => {
  // Primary behavior for this requirement: CSE_KMS plus a KMS key passes.
  it('passes when CSE_KMS encryption is configured with a KMS key ARN', () => {
    const { adapter, context } = bind({
      EncryptionOption: 'CSE_KMS',
      KmsKey: 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    });

    expect(ath001Control.run(adapter, context)).toBeNull();
  });

  it('passes when CSE_KMS encryption references a KMS key resource in the template', () => {
    // !Ref QueryKey / !GetAtt QueryKey.Arn both preprocess to the logical ID string.
    const { adapter, context } = bind({
      EncryptionOption: 'CSE_KMS',
      KmsKey: 'QueryKey',
    });

    expect(ath001Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: same supported option, but the KMS key required by KMS-based
  // options is absent, so the control must report a finding.
  it('flags CSE_KMS encryption when no KMS key is specified', () => {
    const { adapter, context } = bind({
      EncryptionOption: 'CSE_KMS',
    });

    const result = ath001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('ATH-001');
    expect(result!.resourceName).toBe(LOGICAL_ID);
    expect(result!.resourceType).toBe('AWS::Athena::WorkGroup');
  });
});
