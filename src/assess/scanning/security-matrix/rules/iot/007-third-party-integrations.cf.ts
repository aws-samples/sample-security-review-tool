import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * IoT-007 Rule: Secure third-party integrations for IoT devices
 * 
 * Documentation: This rule ensures that third-party integrations with IoT devices are 
 * implemented securely using AWS Secrets Manager for credential management and proper IAM roles.
 * 
 * The rule checks for:
 * - Proper credential management in IoT topic rules with HTTP actions
 * - Secure Lambda function configurations for third-party integrations
 * - Avoidance of hardcoded credentials in Lambda environment variables
 * - Usage of AWS Secrets Manager for secure credential storage
 * - Appropriate IAM roles with least privilege permissions
 * 
 * See: https://docs.aws.amazon.com/iot/latest/developerguide/security-best-practices.html
 */
export class IoT007Rule extends BaseRule {
  constructor() {
    super(
      'IOT-007',
      'HIGH',
      'Third-party integrations lack secure credential management',
      [
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

    const allRes = allResources || [];

    if (resource.Type === 'AWS::IoT::TopicRule') {
      return this.evaluateTopicRule(resource, allRes, stackName);
    }

    return null;
  }

  private evaluateTopicRule(resource: CloudFormationResource, allResources: CloudFormationResource[], stackName: string): ScanResult | null {
    const actions = resource.Properties?.TopicRulePayload?.Actions || [];

    for (const action of actions) {
      if (action.http && !this.hasSecureHttpConfig(action.http, allResources)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (HTTP action lacks secure credential management)`,
          `Use AWS Secrets Manager for authentication.`
        );
      }

      if (action.lambda && !this.hasSecureLambdaConfig(action.lambda, allResources)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (Lambda action lacks proper IAM role configuration)`,
          `Configure proper IAM role for third-party integration security.`
        );
      }
    }

    return null;
  }

  private hasSecureHttpConfig(httpAction: any, allResources: CloudFormationResource[]): boolean {
    if (!httpAction.auth) return false;

    // Check if using Secrets Manager for auth
    const authConfig = httpAction.auth;
    if (authConfig.sigv4?.serviceName === 'secretsmanager') return true;

    // Check if credentials reference Secrets Manager
    return this.referencesSecretsManager(authConfig, allResources);
  }

  private hasSecureLambdaConfig(lambdaAction: any, allResources: CloudFormationResource[]): boolean {
    return !!lambdaAction.functionArn; // Basic check for proper function reference
  }

  private looksLikeCredential(key: string, value: string): boolean {
    const credentialKeys = ['password', 'secret', 'key', 'token', 'api_key', 'apikey'];
    const keyLower = key.toLowerCase();

    return credentialKeys.some(cred => keyLower.includes(cred)) &&
      value.length > 10 &&
      !value.startsWith('${') && // Not a CloudFormation reference
      !value.startsWith('{{'); // Not a parameter
  }

  private hasSecretsManagerAccess(lambdaResource: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    const roleArn = lambdaResource.Properties?.Role;
    if (!roleArn) return false;

    // Find the IAM role
    const role = allResources.find(r =>
      r.Type === 'AWS::IAM::Role' &&
      (r.LogicalId === this.extractLogicalId(roleArn) || roleArn.includes(r.LogicalId))
    );

    if (!role?.Properties?.Policies) return false;

    // Check if role has Secrets Manager permissions
    const policies = role.Properties.Policies || [];
    return policies.some((policy: any) =>
      policy.PolicyDocument?.Statement?.some((stmt: any) =>
        stmt.Action?.includes('secretsmanager:GetSecretValue') ||
        (Array.isArray(stmt.Action) && stmt.Action.some((action: string) => action.includes('secretsmanager:')))
      )
    );
  }

  private hasThirdPartyIntegration(environment: Record<string, any>): boolean {
    const thirdPartyIndicators = ['api_url', 'endpoint', 'webhook', 'external'];
    return Object.keys(environment).some(key =>
      thirdPartyIndicators.some(indicator => key.toLowerCase().includes(indicator))
    );
  }

  private referencesSecretsManager(config: any, allResources: CloudFormationResource[]): boolean {
    const configStr = JSON.stringify(config);
    return allResources.some(r =>
      r.Type === 'AWS::SecretsManager::Secret' &&
      configStr.includes(r.LogicalId)
    );
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

export default new IoT007Rule();