import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * CP2 Rule: Use AWS Secrets Manager in AWS CodePipeline to rotate, manage, and retrieve credentials
 * 
 * Use AWS Secrets Manager for credentials, keys, and certificates. Use AWS SSM Parameter Store for configuration data.
 */
export class CodePipeline002Rule extends BaseRule {
  constructor() {
    super(
      'CODEPIPELINE-002',
      'HIGH',
      'CodePipeline contains hardcoded credentials or insecure parameter references',
      ['AWS::CodePipeline::Pipeline']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    const stages = resource.Properties?.Stages || [];
    
    for (const stage of stages) {
      const actions = stage.Actions || [];
      for (const action of actions) {
        const hasInsecureCredentials = this.hasInsecureCredentials(action);
        if (hasInsecureCredentials) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            'Replace hardcoded credentials with Secrets Manager references: use "{{resolve:secretsmanager:secret-name:SecretString:key}}" or SSM Parameter Store "{{resolve:ssm:parameter-name}}" for configuration data'
          );
        }
      }
    }

    return null;
  }

  private hasInsecureCredentials(action: any): boolean {
    const configuration = action.Configuration || {};
    
    // Check for common credential fields with hardcoded values
    const credentialFields = [
      'AccessKey', 'SecretKey', 'Password', 'Token', 'ApiKey', 'ClientSecret',
      'PrivateKey', 'Certificate', 'Username', 'OAuthToken', 'ConnectionArn'
    ];

    for (const field of credentialFields) {
      const value = configuration[field];
      if (typeof value === 'string') {
        // Check if it's a hardcoded value (not a parameter reference)
        const isParameterReference = value.includes('{{resolve:') || 
                                   value.includes('${') || 
                                   typeof value === 'object';
        
        if (!isParameterReference && value.length > 0) {
          return true;
        }
      }
    }

    // Check for GitHub/Bitbucket tokens that should use Secrets Manager
    if (action.ActionTypeId?.Provider === 'GitHub' || action.ActionTypeId?.Provider === 'Bitbucket') {
      const oauthToken = configuration.OAuthToken;
      if (typeof oauthToken === 'string' && !oauthToken.includes('{{resolve:secretsmanager:')) {
        return true;
      }
    }

    return false;
  }
}

export default new CodePipeline002Rule();