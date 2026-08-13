import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.cfn.js';
import { DEFAULT_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'ConversationalBot';

function buildTemplate(slot: Record<string, unknown>): Template {
  return {
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::Lex::Bot',
        Properties: {
          Name: 'support-bot',
          RoleArn: 'arn:aws:iam::123456789012:role/lex-role',
          DataPrivacy: { ChildDirected: false },
          IdleSessionTTLInSeconds: 300,
          BotLocales: [
            {
              LocaleId: 'en_US',
              NluConfidenceThreshold: 0.4,
              Intents: [
                {
                  Name: 'CollectPayment',
                  SampleUtterances: [{ Utterance: 'pay my bill' }],
                  Slots: [slot],
                },
              ],
            },
          ],
        },
      } as unknown as Resource,
    },
  } as unknown as Template;
}

function run(slot: Record<string, unknown>): ScanResult | null {
  const template = buildTemplate(slot);
  const resource = template.Resources![LOGICAL_ID];
  const context: CfnContext = {
    stackName: 'lex-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
  const adapter = new Lex002CfnAdapterFactory().bind(context);
  return lex002Control.run(adapter, context);
}

describe('LEX-002 CloudFormation — REQ-03: slot with no value obfuscation configuration at all', () => {
  // Primary behavior owned by this requirement: obfuscation is opt-in, so an
  // absent ObfuscationSetting means slot values are logged in cleartext -> flag.
  it('flags a slot that has no ObfuscationSetting property', () => {
    const result = run({
      Name: 'CardNumber',
      SlotTypeName: 'AMAZON.Number',
      ValueElicitationSetting: {
        SlotConstraint: 'Required',
      },
    });

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LEX-002');
    expect(result!.resourceType).toBe('AWS::Lex::Bot');
    expect(result!.resourceName).toBe(LOGICAL_ID);
    expect(result!.issue).toContain('CardNumber');
  });

  // Opposite outcome: same slot, but obfuscation explicitly configured to the
  // masking value -> no finding.
  it('does not flag a slot whose ObfuscationSetting is DefaultObfuscation', () => {
    const result = run({
      Name: 'CardNumber',
      SlotTypeName: 'AMAZON.Number',
      ObfuscationSetting: { ObfuscationSettingType: DEFAULT_OBFUSCATION },
      ValueElicitationSetting: {
        SlotConstraint: 'Required',
      },
    });

    expect(result).toBeNull();
  });
});
