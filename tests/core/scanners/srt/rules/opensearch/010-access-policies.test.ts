import { describe, it, expect } from 'vitest';
import { ESH010Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/opensearch/010-access-policies.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ESH010Rule', () => {
  const rule = new ESH010Rule();
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
    expect(rule.id).toBe('ESH-010');
    expect(rule.priority).toBe('HIGH');
    expect(rule.appliesTo('AWS::OpenSearchService::Domain')).toBe(true);
    expect(rule.appliesTo('AWS::Elasticsearch::Domain')).toBe(false);
  });

  it('should detect missing AccessPolicies', () => {
    const domain = createOpenSearchResource();
    const result = rule.evaluate(domain, stackName);
    
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('OpenSearch domain has overly permissive access policies');
  });

  it('should detect overly permissive policies', () => {
    const domain = createOpenSearchResource({
      AccessPolicies: {
        Version: '2012-10-17',
        Statement: [{
          Effect: 'Allow',
          Principal: '*',
          Action: 'es:*',
          Resource: '*'
        }]
      }
    });
    const result = rule.evaluate(domain, stackName);
    
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Access policy allows unrestricted access');
  });

  it('should pass with restrictive policies', () => {
    const domain = createOpenSearchResource({
      AccessPolicies: {
        Version: '2012-10-17',
        Statement: [{
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::123456789012:user/test-user' },
          Action: 'es:ESHttpGet',
          Resource: 'arn:aws:es:us-east-1:123456789012:domain/test-domain/*'
        }]
      }
    });
    const result = rule.evaluate(domain, stackName);
    
    expect(result).toBeNull();
  });


});