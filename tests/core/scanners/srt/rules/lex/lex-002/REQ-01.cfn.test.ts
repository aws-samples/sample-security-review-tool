import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.cfn.js';
import type { Lex002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex002CfnAdapterFactory();

function buildBot(obfuscationSettingType: string): Resource {
  return {
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
              SampleUtterances: [{ Utterance: 'I want to order' }],
              Slots: [
                {
                  Name: 'CreditCardNumber',
                  SlotTypeName: 'AMAZON.Number',
                  ObfuscationSetting: {
                    ObfuscationSettingType: obfuscationSettingType,
                  },
                  ValueElicitationSetting: {
                    SlotConstraint: 'Required',
                  },
                },
              ],
            },
          ],
        },
      ],
    },
  } as unknown as Resource;
}

function buildContext(resource: Resource): CfnContext {
  const template = {
    Resources: {
      OrderBot: resource,
    },
  } as unknown as Template;

  return {
    stackName: 'lex-stack',
    template,
    resource,
    logicalId: 'OrderBot',
  };
}

function runControl(resource: Resource) {
  const context = buildContext(resource);
  const adapter = factory.bind(context) as Lex002Adapter;
  return lex002Control.run(adapter, context);
}

describe('LEX-002 CloudFormation - slot value obfuscation', () => {
  it('applies to AWS::Lex::Bot resources', () => {
    expect(factory.appliesTo('AWS::Lex::Bot')).toBe(true);
  });

  // Primary behavior for this requirement: DefaultObfuscation is the compliant state.
  it('passes when the slot uses the default obfuscation type', () => {
    const result = runControl(buildBot('DefaultObfuscation'));
    expect(result).toBeNull();
  });

  // Opposite outcome: same slot, obfuscation present but disabled ("None") must be flagged.
  it('flags a slot whose obfuscation setting type is None', () => {
    const result = runControl(buildBot('None'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
    expect(result?.resourceName).toBe('OrderBot');
  });
});
