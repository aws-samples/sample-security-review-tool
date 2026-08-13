import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { DEFAULT_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import { Lex002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex002CfnAdapterFactory();

interface SlotFixture {
  readonly name: string;
  readonly obfuscationType: string;
}

function buildTemplate(slots: SlotFixture[]): Template {
  return {
    Resources: {
      ConversationalBot: {
        Type: 'AWS::Lex::Bot',
        Properties: {
          Name: 'order-bot',
          RoleArn: 'arn:aws:iam::123456789012:role/lex-bot-role',
          DataPrivacy: { ChildDirected: false },
          IdleSessionTTLInSeconds: 300,
          BotLocales: [
            {
              LocaleId: 'en_US',
              NluConfidenceThreshold: 0.4,
              Intents: [
                {
                  Name: 'PlaceOrder',
                  SampleUtterances: [{ Utterance: 'place an order' }],
                  Slots: slots.map(slot => ({
                    Name: slot.name,
                    SlotTypeName: 'AMAZON.AlphaNumeric',
                    ObfuscationSetting: { ObfuscationSettingType: slot.obfuscationType },
                    ValueElicitationSetting: {
                      SlotConstraint: 'Required',
                      PromptSpecification: {
                        MaxRetries: 2,
                        MessageGroupsList: [
                          { Message: { PlainTextMessage: { Value: `Provide ${slot.name}` } } },
                        ],
                      },
                    },
                  })),
                },
              ],
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function buildContext(template: Template): CfnContext {
  return {
    stackName: 'lex-stack',
    template,
    resource: template.Resources!['ConversationalBot'],
    logicalId: 'ConversationalBot',
  };
}

function run(slots: SlotFixture[]) {
  const context = buildContext(buildTemplate(slots));
  return lex002Control.run(factory.bind(context), context);
}

describe('LEX-002 CloudFormation - obfuscation must be enabled on every bot slot', () => {
  // Primary behavior owned by LEX-002: any single slot with obfuscation disabled is flagged.
  it('flags the bot when one of several slots has obfuscation disabled while siblings are obfuscated', () => {
    const result = run([
      { name: 'CardNumber', obfuscationType: DEFAULT_OBFUSCATION },
      { name: 'SecurityCode', obfuscationType: 'None' },
      { name: 'ZipCode', obfuscationType: DEFAULT_OBFUSCATION },
    ]);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LEX-002');
    expect(result!.resourceType).toBe('AWS::Lex::Bot');
    expect(result!.resourceName).toBe('ConversationalBot');
    expect(result!.issue).toContain('SecurityCode');
    expect(result!.issue).not.toContain('CardNumber');
    expect(result!.issue).not.toContain('ZipCode');
  });

  it('flags every unobfuscated slot when more than one slot is disabled', () => {
    const result = run([
      { name: 'CardNumber', obfuscationType: 'None' },
      { name: 'SecurityCode', obfuscationType: DEFAULT_OBFUSCATION },
      { name: 'ZipCode', obfuscationType: 'None' },
    ]);

    expect(result).not.toBeNull();
    expect(result!.issue).toContain('CardNumber');
    expect(result!.issue).toContain('ZipCode');
  });

  // Opposite outcome: identical multi-slot bot where the offending slot's obfuscation is enabled.
  it('does not flag when all slots in the bot have obfuscation enabled', () => {
    const result = run([
      { name: 'CardNumber', obfuscationType: DEFAULT_OBFUSCATION },
      { name: 'SecurityCode', obfuscationType: DEFAULT_OBFUSCATION },
      { name: 'ZipCode', obfuscationType: DEFAULT_OBFUSCATION },
    ]);

    expect(result).toBeNull();
  });
});
