import { describe, it, expect } from 'vitest';
import { ESH001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/opensearch/001-vpc-deployment.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ESH001Rule', () => {
  const rule = new ESH001Rule();
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
    expect(rule.id).toBe('ESH-001');
    expect(rule.priority).toBe('HIGH');
    expect(rule.appliesTo('AWS::OpenSearchService::Domain')).toBe(true);
    expect(rule.appliesTo('AWS::Elasticsearch::Domain')).toBe(false);
  });

  it('should detect missing VPCOptions', () => {
    const domain = createOpenSearchResource();
    const result = rule.evaluate(domain, stackName);
    
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('OpenSearch domain not deployed in VPC');
  });

  it('should detect missing SubnetIds', () => {
    const domain = createOpenSearchResource({
      VPCOptions: {}
    });
    const result = rule.evaluate(domain, stackName);
    
    expect(result).not.toBeNull();
  });

  it('should pass with proper VPC configuration', () => {
    const domain = createOpenSearchResource({
      VPCOptions: {
        SubnetIds: ['subnet-123', 'subnet-456']
      }
    });
    const result = rule.evaluate(domain, stackName);
    
    expect(result).toBeNull();
  });


});