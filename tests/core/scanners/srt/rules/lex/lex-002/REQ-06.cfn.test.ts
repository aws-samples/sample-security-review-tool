import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { DEFAULT_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import { Lex002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex002CfnAdapterFactory();

function slot(name: string, obfuscationType: string) {
  return {
    Name: name,
    SlotTypeName: 'AMAZON.AlphaNumeric',
    ValueElicitationSetting: {
      SlotConstraint: 'Required',
    },
    ObfuscationSetting: {
      ObfuscationSettingType: obfuscationType,
    },
  };
}

function botResource(obfuscationType: string): Resource {
  return {
    Type: 'AWS::Lex::Bot',
    Properties: {
      Name: 'CustomerServiceBot',
      RoleArn: 'arn:aws:iam::123456789012:role/lex-bot-role',
      DataPrivacy: { ChildDirected: false },
      IdleSessionTTLInSeconds: 300,
      BotLocales: [
        {
          LocaleId: 'en_US',
          NluConfidenceThreshold: 0.4,
          Intents: [
            {
              Name: 'CollectCardDetails',
              Slots: [slot('CardNumber', obfuscationType), slot('CardPin', obfuscationType)],
            },
            {
              Name: 'VerifyIdentity',
              Slots: [slot('SocialSecurityNumber', obfuscationType)],
            },
          ],
        },
        {
          LocaleId: 'es_US',
          NluConfidenceThreshold: 0.4,
          Intents: [
            {
              Name: 'RecogerDatosTarjeta',
              Slots: [slot('NumeroTarjeta', obfuscationType)],
            },
          ],
        },
      ],
    },
  } as unknown as Resource;
}

function runControl(resource: Resource) {
  const template = { Resources: { ConversationalBot: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'lex-stack',
    template,
    resource,
    logicalId: 'ConversationalBot',
  };
  return lex002Control.run(factory.bind(context), context);
}

describe('LEX-002 CloudFormation — slot value obfuscation', () => {
  // Primary behavior owned by LEX-002 (REQ-06): all slots across all locales/intents obfuscated -> pass
  it('passes when every slot in every locale and intent has obfuscation enabled', () => {
    const result = runControl(botResource(DEFAULT_OBFUSCATION));

    expect(result).toBeNull();
  });

  // Opposite outcome: same fixture, obfuscation type present but set to the disabled value
  it('flags the bot when slots specify obfuscation type None instead of masking', () => {
    const result = runControl(botResource('None'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceName).toBe('ConversationalBot');
    expect(result?.issue).toContain('CardNumber');
    expect(result?.issue).toContain('NumeroTarjeta');
  });
});
