import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Sec004Rule extends BaseRule {
  constructor() {
    super(
      'SEC-004',
      'HIGH',
      'Secret has overly permissive access policy',
      ['AWS::SecretsManager::ResourcePolicy']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // Note: AWS::SecretsManager::Secret does not have a ResourcePolicy property in CloudFormation
    // Resource policies for secrets are managed via AWS::SecretsManager::ResourcePolicy resources

    if (resource.Type === 'AWS::SecretsManager::ResourcePolicy') {
      // Check if the resource policy is overly permissive
      const resourcePolicy = resource.Properties?.ResourcePolicy;

      if (resourcePolicy && this.isOverlyPermissivePolicy(resourcePolicy)) {
        return this.createScanResult(
          resource,
          stackName,
          'Secret has overly permissive access policy',
          `Modify the resource policy to follow the principle of least privilege by restricting access to specific principals, actions, and resources. Avoid using wildcards (*) in principals, actions, and resources.`
        );
      }
    }

    return null;
  }

  private isOverlyPermissivePolicy(policy: any): boolean {
    // Check if the policy is overly permissive

    // If the policy is a string, parse it
    let policyObj = policy;
    if (typeof policy === 'string') {
      try {
        policyObj = JSON.parse(policy);
      } catch (error) {
        // If we can't parse the policy, assume it's not overly permissive
        return false;
      }
    }

    // Check if the policy has a Statement
    const statements = policyObj.Statement;

    if (!statements || !Array.isArray(statements)) {
      // If there are no statements, assume it's not overly permissive
      return false;
    }

    // Check each statement
    for (const statement of statements) {
      // Check if the statement is an Allow statement
      if (statement.Effect === 'Allow') {
        // Check if the Principal is overly permissive
        const principal = statement.Principal;

        if (principal) {
          // Check if the Principal is '*'
          if (principal === '*') {
            return true;
          }

          // Check if the Principal has an AWS field with '*'
          if (principal.AWS) {
            if (principal.AWS === '*') {
              return true;
            }

            if (Array.isArray(principal.AWS) && principal.AWS.includes('*')) {
              return true;
            }
          }
        }

        // Check if the Action is overly permissive
        const action = statement.Action;

        if (action) {
          // Check if the Action is '*'
          if (action === '*') {
            return true;
          }

          // Check if the Action is an array with '*'
          if (Array.isArray(action) && action.includes('*')) {
            return true;
          }

          // Check if the Action includes wildcard actions
          if (typeof action === 'string' && action.includes('*')) {
            return true;
          }

          if (Array.isArray(action)) {
            for (const act of action) {
              if (typeof act === 'string' && act.includes('*')) {
                return true;
              }
            }
          }
        }

        // Check if the Resource is overly permissive
        const resource = statement.Resource;

        if (resource) {
          // Check if the Resource is '*'
          if (resource === '*') {
            return true;
          }

          // Check if the Resource is an array with '*'
          if (Array.isArray(resource) && resource.includes('*')) {
            return true;
          }
        }
      }
    }

    return false;
  }
}

export default new Sec004Rule();
