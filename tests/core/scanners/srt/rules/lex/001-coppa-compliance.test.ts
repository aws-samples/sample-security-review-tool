import { describe, it, expect } from 'vitest';
import { Lex001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/lex/001-coppa-compliance.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Lex001Rule', () => {
  const rule = new Lex001Rule();
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

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('LEX-001');
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
    it('should flag bot with missing Properties', () => {
      // Arrange
      const bot = {
        Type: 'AWS::Lex::Bot',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Lex::Bot');
      expect(result?.resourceName).toBe('MissingProperties');
      expect(result?.issue).toContain('Amazon Lex bot does not have DataPrivacy.ChildDirected set to true for COPPA compliance');
      expect(result?.fix).toContain('Set DataPrivacy.ChildDirected property to \'true\' to comply with COPPA');
    });

    it('should flag bot with missing DataPrivacy property', () => {
      // Arrange
      const bot = createLexBotResource();
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Lex::Bot');
      expect(result?.resourceName).toBe('TestLexBot');
      expect(result?.issue).toContain('Amazon Lex bot does not have DataPrivacy.ChildDirected set to true for COPPA compliance');
      expect(result?.fix).toContain('Set DataPrivacy.ChildDirected property to \'true\' to comply with COPPA');
    });

    it('should flag bot with missing ChildDirected property', () => {
      // Arrange
      const bot = createLexBotResource({
        DataPrivacy: {}
      });
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Lex::Bot');
      expect(result?.resourceName).toBe('TestLexBot');
      expect(result?.issue).toContain('Amazon Lex bot does not have DataPrivacy.ChildDirected set to true for COPPA compliance');
      expect(result?.fix).toContain('Set DataPrivacy.ChildDirected property to \'true\' to comply with COPPA');
    });

    it('should flag bot with ChildDirected set to false', () => {
      // Arrange
      const bot = createLexBotResource({
        DataPrivacy: {
          ChildDirected: false
        }
      });
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Lex::Bot');
      expect(result?.resourceName).toBe('TestLexBot');
      expect(result?.issue).toContain('Amazon Lex bot does not have DataPrivacy.ChildDirected set to true for COPPA compliance');
      expect(result?.fix).toContain('Set DataPrivacy.ChildDirected property to \'true\' to comply with COPPA');
    });

    it('should not flag bot with ChildDirected set to true', () => {
      // Arrange
      const bot = createLexBotResource({
        DataPrivacy: {
          ChildDirected: true
        }
      });
      
      // Act
      const result = rule.evaluate(bot, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should flag bot with ChildDirected as CloudFormation intrinsic function', () => {
      // Arrange
      const bot = createLexBotResource({
        DataPrivacy: {
          ChildDirected: { Ref: 'ChildDirectedParameter' }
        }
      });
      
      // Act
      const result = rule.evaluate(bot, stackName, []);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Lex::Bot');
      expect(result?.resourceName).toBe('TestLexBot');
      expect(result?.issue).toContain('Amazon Lex bot does not have DataPrivacy.ChildDirected set to true for COPPA compliance');
      expect(result?.fix).toContain('Set DataPrivacy.ChildDirected property to an explicit boolean value');
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
  });
});
