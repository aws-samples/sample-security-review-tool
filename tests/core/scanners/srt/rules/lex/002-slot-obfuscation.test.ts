import { describe, it, expect } from 'vitest';
import { Lex002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/lex/002-slot-obfuscation.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Lex002Rule', () => {
  const rule = new Lex002Rule();
  const stackName = 'test-stack';

  // Helper function to create Lex Bot test resources
  function createLexBotResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::Lex::Bot',
      Properties: {
        Name: 'TestBot',
        RoleArn: 'arn:aws:iam::123456789012:role/LexBotRole',
        ...props
      },
      LogicalId: props.LogicalId || 'TestLexBot'
    };
  }

  // Helper function to create a slot with specific obfuscation settings
  function createSlot(name: string, obfuscationSettingType?: string | Record<string, any>): any {
    const slot: any = {
      Name: name,
      SlotTypeName: 'AMAZON.AlphaNumeric'
    };

    if (obfuscationSettingType !== undefined) {
      slot.ObfuscationSetting = {
        ObfuscationSettingType: obfuscationSettingType
      };
    }

    return slot;
  }

  // Helper function to create a bot with slots
  function createBotWithSlots(slots: any[]): CloudFormationResource {
    return createLexBotResource({
      BotLocales: [
        {
          LocaleId: 'en_US',
          Intents: [
            {
              Name: 'TestIntent',
              Slots: slots
            }
          ]
        }
      ]
    });
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('LEX-002');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to Lex Bot resources', () => {
      expect(rule.appliesTo('AWS::Lex::Bot')).toBe(true);
      expect(rule.appliesTo('AWS::Lex::BotAlias')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Bot Resource Tests', () => {
    it('should not flag bot with missing Properties', () => {
      // Arrange
      const bot = {
        Type: 'AWS::Lex::Bot',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag bot with no BotLocales', () => {
      // Arrange
      const bot = createLexBotResource();
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag bot with BotLocales but no Intents', () => {
      // Arrange
      const bot = createLexBotResource({
        BotLocales: [
          {
            LocaleId: 'en_US'
          }
        ]
      });
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag bot with Intents but no Slots', () => {
      // Arrange
      const bot = createLexBotResource({
        BotLocales: [
          {
            LocaleId: 'en_US',
            Intents: [
              {
                Name: 'TestIntent'
              }
            ]
          }
        ]
      });
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag bot with Slots but no ObfuscationSetting', () => {
      // Arrange
      const bot = createBotWithSlots([
        createSlot('SlotWithoutObfuscation')
      ]);
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag bot with ObfuscationSettingType set to DefaultObfuscation', () => {
      // Arrange
      const bot = createBotWithSlots([
        createSlot('SlotWithDefaultObfuscation', 'DefaultObfuscation')
      ]);
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should flag bot with ObfuscationSettingType set to None', () => {
      // Arrange
      const bot = createBotWithSlots([
        createSlot('SlotWithNoObfuscation', 'None')
      ]);
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Lex::Bot');
      expect(result?.resourceName).toBe('TestLexBot');
      expect(result?.issue).toContain('Amazon Lex V2 bot contains slots with obfuscation explicitly disabled');
      expect(result?.issue).toContain('SlotWithNoObfuscation');
      expect(result?.fix).toContain('Remove ObfuscationSetting property or set ObfuscationSettingType to \'DefaultObfuscation\'');
    });

    it('should flag bot with multiple slots, some with ObfuscationSettingType set to None', () => {
      // Arrange
      const bot = createBotWithSlots([
        createSlot('SlotWithDefaultObfuscation', 'DefaultObfuscation'),
        createSlot('SlotWithNoObfuscation1', 'None'),
        createSlot('SlotWithoutObfuscation'),
        createSlot('SlotWithNoObfuscation2', 'None')
      ]);
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Lex::Bot');
      expect(result?.resourceName).toBe('TestLexBot');
      expect(result?.issue).toContain('Amazon Lex V2 bot contains slots with obfuscation explicitly disabled');
      expect(result?.issue).toContain('SlotWithNoObfuscation1');
      expect(result?.issue).toContain('SlotWithNoObfuscation2');
      expect(result?.issue).toContain('Found 2 slot(s) with obfuscation explicitly disabled');
    });

    it('should handle bot with ObfuscationSettingType as a CloudFormation intrinsic function', () => {
      // Arrange
      const bot = createBotWithSlots([
        createSlot('SlotWithIntrinsicFunction', { Ref: 'ObfuscationSettingParameter' })
      ]);
      
      // Act
      const result = rule.evaluate(bot, stackName, []);
      
      // Assert
      expect(result).toBeNull(); // Since we can't resolve the intrinsic function, it should not flag
    });

    it('should handle bot with multiple locales and intents', () => {
      // Arrange
      const bot = createLexBotResource({
        BotLocales: [
          {
            LocaleId: 'en_US',
            Intents: [
              {
                Name: 'Intent1',
                Slots: [
                  createSlot('Slot1', 'DefaultObfuscation')
                ]
              }
            ]
          },
          {
            LocaleId: 'es_ES',
            Intents: [
              {
                Name: 'Intent2',
                Slots: [
                  createSlot('Slot2', 'None')
                ]
              },
              {
                Name: 'Intent3',
                Slots: [
                  createSlot('Slot3', 'DefaultObfuscation')
                ]
              }
            ]
          }
        ]
      });
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Lex::Bot');
      expect(result?.resourceName).toBe('TestLexBot');
      expect(result?.issue).toContain('Amazon Lex V2 bot contains slots with obfuscation explicitly disabled');
      expect(result?.issue).toContain('Slot2');
      expect(result?.issue).toContain('Found 1 slot(s) with obfuscation explicitly disabled');
    });
  });

  describe('Edge Cases', () => {
    it('should ignore non-applicable resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };
      
      // Act
      const result = rule.evaluate(resource, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should handle malformed bot structure gracefully', () => {
      // Arrange
      const bot = createLexBotResource({
        BotLocales: 'not-an-array' // Intentionally malformed
      });
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).toBeNull(); // Should not throw an error
    });

    it('should handle malformed slots structure gracefully', () => {
      // Arrange
      const bot = createLexBotResource({
        BotLocales: [
          {
            LocaleId: 'en_US',
            Intents: [
              {
                Name: 'TestIntent',
                Slots: 'not-an-array' // Intentionally malformed
              }
            ]
          }
        ]
      });
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).toBeNull(); // Should not throw an error
    });

    it('should handle undefined values gracefully', () => {
      // Arrange
      const bot = createLexBotResource({
        BotLocales: [
          {
            LocaleId: 'en_US',
            Intents: [
              {
                Name: 'TestIntent',
                Slots: [
                  {
                    Name: 'SlotWithUndefinedObfuscation',
                    ObfuscationSetting: undefined
                  }
                ]
              }
            ]
          }
        ]
      });
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).toBeNull(); // Should not throw an error
    });
  });
});
