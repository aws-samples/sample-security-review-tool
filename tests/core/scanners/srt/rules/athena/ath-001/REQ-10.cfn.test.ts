import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AnalyticsWorkGroup';

function buildContext(encryptionConfiguration: unknown): CfnContext {
  const resource = {
    Type: 'AWS::Athena::WorkGroup',
    Properties: {
      Name: 'analytics',
      WorkGroupConfiguration: {
        ResultConfiguration: {
          OutputLocation: 's3://query-results/prefix/',
          EncryptionConfiguration: encryptionConfiguration,
        },
      },
    },
  } as unknown as Resource;

  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function run(encryptionConfiguration: unknown) {
  const context = buildContext(encryptionConfiguration);
  const adapter = new Ath001CfnAdapterFactory().bind(context);
  return ath001Control.run(adapter, context);
}

describe('ATH-001 REQ-10 (CloudFormation): unsupported or empty query result encryption option', () => {
  // Primary behavior owned by this requirement: encryption settings present but the
  // option value is empty or not one of SSE_S3 / SSE_KMS / CSE_KMS -> flag.
  it('flags a workgroup whose EncryptionOption is an empty string', () => {
    const result = run({ EncryptionOption: '' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::Athena::WorkGroup');
  });

  it('flags a workgroup whose EncryptionOption is only whitespace', () => {
    expect(run({ EncryptionOption: '   ' })).not.toBeNull();
  });

  it('flags a workgroup whose EncryptionOption is outside the supported set', () => {
    expect(run({ EncryptionOption: 'AES256' })).not.toBeNull();
  });

  it('flags an unsupported EncryptionOption even when a KMS key is supplied', () => {
    expect(run({
      EncryptionOption: 'SSE_S3_KMS',
      KmsKey: 'arn:aws:kms:us-east-1:123456789012:key/abc',
    })).not.toBeNull();
  });

  it('flags a lowercase spelling of a supported option as unrecognized', () => {
    expect(run({ EncryptionOption: 'sse_s3' })).not.toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict — the same settings block
  // with a supported option value instead of an unsupported one.
  it('does not flag a workgroup whose EncryptionOption is the supported SSE_S3 value', () => {
    expect(run({ EncryptionOption: 'SSE_S3' })).toBeNull();
  });
});
