import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Sec001Rule extends BaseRule {
  constructor() {
    super(
      'SEC-001',
      'HIGH',
      'Sensitive data not stored in AWS Secrets Manager',
      [
        'AWS::Lambda::Function',
        // 'AWS::ECS::TaskDefinition' is removed as it's handled by ECS-002 rule
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // ECS TaskDefinition checks are now handled by ECS-002 rule
    if (resource.Type === 'AWS::ECS::TaskDefinition') {
      return null; // Skip these checks as they're handled by ECS-002 rule
    }

    if (resource.Type === 'AWS::Lambda::Function') {
      const environment = resource.Properties?.Environment;
      if (!environment) return null;

      const variables = environment.Variables;
      if (!variables) return null;

      // Check for sensitive variable names
      const sensitiveKeywords = ['password', 'passwd', 'pwd', 'secret', 'key', 'token', 'credential', 'auth'];

      for (const key in variables) {
        const lowerKey = key.toLowerCase();
        if (sensitiveKeywords.some(keyword => lowerKey.includes(keyword))) {
          // Check if the value is a reference to Secrets Manager
          const value = variables[key];
          if (typeof value === 'string' && !value.includes('secretsmanager')) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `Replace hardcoded sensitive values in Lambda environment variables with references to AWS Secrets Manager using dynamic references like '{{resolve:secretsmanager:MySecret:SecretString:password}}' or CloudFormation functions.`
            );
          }
        }
      }
    }

    if (resource.Type === 'AWS::ECS::TaskDefinition') {
      const containerDefinitions = resource.Properties?.ContainerDefinitions;
      if (!containerDefinitions || !Array.isArray(containerDefinitions)) return null;

      for (const container of containerDefinitions) {
        const environment = container.Environment;
        if (!environment || !Array.isArray(environment)) continue;

        // Check for sensitive variable names
        const sensitiveKeywords = ['password', 'passwd', 'pwd', 'secret', 'key', 'token', 'credential', 'auth'];

        for (const env of environment) {
          const name = env.Name;
          if (!name) continue;

          const lowerName = name.toLowerCase();
          if (sensitiveKeywords.some(keyword => lowerName.includes(keyword))) {
            // Check if the value is a reference to Secrets Manager
            const value = env.Value;
            if (typeof value === 'string' && !value.includes('secretsmanager')) {
              return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Replace hardcoded sensitive values in ECS Task Definition environment variables with references to AWS Secrets Manager. Use the 'secrets' property instead of 'environment' for sensitive data, referencing Secrets Manager ARNs.`
              );
            }
          }
        }
      }
    }

    return null;
  }
}

export default new Sec001Rule();
