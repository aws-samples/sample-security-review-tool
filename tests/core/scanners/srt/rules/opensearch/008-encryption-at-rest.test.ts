import { describe, it, expect } from 'vitest';
import { ESH008Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/opensearch/008-encryption-at-rest.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ESH008Rule', () => {
  const rule = new ESH008Rule();
  const stackName = 'test-stack';

  function createOpenSearchResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::OpenSearchService::Domain',
      Properties: {
        DomainName: 'test-domain',
        ...props
      },
      LogicalId: 'TestOpenSearchDomain'
    };
  }

  it('should have correct rule properties', () => {
    expect(rule.id).toBe('ESH-008');
    expect(rule.priority).toBe('HIGH');
    expect(rule.appliesTo('AWS::OpenSearchService::Domain')).toBe(true);
    expect(rule.appliesTo('AWS::Elasticsearch::Domain')).toBe(false);
  });

  it('should detect missing EncryptionAtRestOptions', () => {
    const domain = createOpenSearchResource();
    const result = rule.evaluate(domain, stackName);
    
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('OpenSearch domain encryption at rest not enabled');
  });

  it('should detect EncryptionAtRestOptions with Enabled set to false', () => {
    const domain = createOpenSearchResource({
      EncryptionAtRestOptions: {
        Enabled: false
      }
    });
    const result = rule.evaluate(domain, stackName);
    
    expect(result).not.toBeNull();
  });

  it('should pass with EncryptionAtRestOptions enabled', () => {
    const domain = createOpenSearchResource({
      EncryptionAtRestOptions: {
        Enabled: true
      }
    });
    const result = rule.evaluate(domain, stackName);
    
    expect(result).toBeNull();
  });


});