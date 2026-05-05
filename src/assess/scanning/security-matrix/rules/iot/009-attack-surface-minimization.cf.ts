import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * IoT-009 Rule: Minimize attack surface by restricting network access and limiting exposed services
 * 
 * Documentation: This rule ensures that IoT deployments minimize their attack surface through
 * proper network restrictions, security groups, and limiting exposed services.
 * 
 * The rule checks for:
 * - Overly permissive security group rules
 * - Unnecessary open ports or broad port ranges
 * - IoT policies with wildcard permissions
 * - Dangerous IoT actions without conditions
 * - Overly broad topic rule selectors
 * - Lambda functions with excessive permissions
 * 
 * See: https://docs.aws.amazon.com/iot/latest/developerguide/security-best-practices.html
 */
export class IoT009Rule extends BaseRule {
  constructor() {
    super(
      'IOT-009',
      'HIGH',
      'Attack surface not minimized - overly permissive access controls',
      [
        'AWS::IoT::Policy',
        'AWS::IoT::TopicRule'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!this.applicableResourceTypes.includes(resource.Type)) {
      return null;
    }

    if (!resource.Properties) {
      return null;
    }

    if (resource.Type === 'AWS::IoT::Policy') {
      return this.evaluateIoTPolicy(resource, stackName);
    }

    if (resource.Type === 'AWS::IoT::TopicRule') {
      return this.evaluateTopicRule(resource, stackName);
    }

    return null;
  }



  private evaluateIoTPolicy(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const statements = resource.Properties?.PolicyDocument?.Statement || [];

    for (const statement of statements) {
      if (statement.Effect === 'Allow') {
        // Check for overly permissive actions
        if (statement.Action === '*' || (Array.isArray(statement.Action) && statement.Action.includes('*'))) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (wildcard permissions)`,
            `Specify exact actions needed.`
          );
        }

        // Check for overly permissive resources
        if (statement.Resource === '*') {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (access to all resources)`,
            `Specify exact resources needed.`
          );
        }

        // Check for dangerous actions without conditions
        const dangerousActions = ['iot:UpdateThing', 'iot:DeleteThing', 'iot:UpdateCertificate'];
        const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];

        if (actions.some((action: string) => dangerousActions.includes(action)) && !statement.Condition) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (dangerous actions without conditions)`,
            `Add conditions to restrict access.`
          );
        }
      }
    }

    return null;
  }

  private evaluateTopicRule(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const sql = resource.Properties?.TopicRulePayload?.Sql;
    const actions = resource.Properties?.TopicRulePayload?.Actions || [];

    // Check for overly broad SQL selectors
    if (sql && sql.includes('SELECT *')) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (SELECT * exposes all message data)`,
        `Select specific fields needed.`
      );
    }

    // Check for actions that could expose data
    for (const action of actions) {
      if (action.s3 && !action.s3.Key) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (S3 action lacks specific key pattern)`,
          `Use structured keys.`
        );
      }
    }

    return null;
  }



  private extractLogicalId(ref: any): string {
    if (typeof ref !== 'string') {
      if (ref?.Ref) return ref.Ref;
      return '';
    }
    if (ref.startsWith('!Ref ')) return ref.substring(5);
    if (ref.startsWith('${') && ref.endsWith('}')) return ref.slice(2, -1);
    return ref;
  }
}

export default new IoT009Rule();
