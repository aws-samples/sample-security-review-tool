import { describe, it, expect } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-14 (CloudFormation)
 * ATH-001: Athena workgroups must have query result encryption enabled using SSE_S3,
 * SSE_KMS, or CSE_KMS, with a KMS key specified when SSE_KMS or CSE_KMS is used.
 *
 * Scenario owned by this file: whether query result encryption settings exist at all
 * depends on a condition that cannot be resolved at analysis time (Fn::If / Fn::ImportValue
 * survive template preprocessing untouched). The analyzer cannot prove the deployed
 * workgroup lacks encryption, so no finding may be raised.
 */

const factory = new Ath001CfnAdapterFactory();

function runControl(resource: Resource) {
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

function workGroup(workGroupConfiguration: unknown): Resource {
  return {
    Type: 'AWS::Athena::WorkGroup',
    Properties: {
      Name: 'analytics-workgroup',
      WorkGroupConfiguration: workGroupConfiguration,
    },
  } as unknown as Resource;
}

describe('ATH-001 REQ-14 (CloudFormation): indeterminate query result encryption settings', () => {
  it('returns no finding when the whole workgroup configuration is an unresolvable Fn::If', () => {
    const result = runControl(
      workGroup({
        'Fn::If': [
          'EncryptResults',
          { ResultConfiguration: { EncryptionConfiguration: { EncryptionOption: 'SSE_S3' } } },
          { ResultConfiguration: {} },
        ],
      }),
    );

    expect(result).toBeNull();
  });

  it('returns no finding when the result configuration is an unresolvable Fn::If', () => {
    const result = runControl(
      workGroup({
        ResultConfiguration: {
          'Fn::If': [
            'EncryptResults',
            { EncryptionConfiguration: { EncryptionOption: 'SSE_KMS', KmsKey: 'arn:aws:kms:us-east-1:123456789012:key/abc' } },
            { OutputLocation: 's3://results/' },
          ],
        },
      }),
    );

    expect(result).toBeNull();
  });

  it('returns no finding when the encryption configuration itself is an unresolvable Fn::If', () => {
    const result = runControl(
      workGroup({
        ResultConfiguration: {
          OutputLocation: 's3://results/',
          EncryptionConfiguration: {
            'Fn::If': [
              'EncryptResults',
              { EncryptionOption: 'SSE_S3' },
              { Ref: 'AWS::NoValue' },
            ],
          },
        },
      }),
    );

    expect(result).toBeNull();
  });

  it('returns no finding when the encryption option is an unresolvable Fn::ImportValue', () => {
    const result = runControl(
      workGroup({
        ResultConfiguration: {
          EncryptionConfiguration: {
            EncryptionOption: { 'Fn::ImportValue': 'SharedEncryptionOption' },
          },
        },
      }),
    );

    expect(result).toBeNull();
  });

  // Opposite outcome: primary behavior for the unsupported-option case is owned by the
  // "missing query result encryption" requirement. Only the resolvability of the
  // encryption option changes relative to the tests above.
  it('flags the workgroup when the encryption option is resolvable but not a supported option', () => {
    const result = runControl(
      workGroup({
        ResultConfiguration: {
          EncryptionConfiguration: {
            EncryptionOption: 'AES256',
          },
        },
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('WorkGroup');
  });
});
