import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEcs002Rule extends BaseTerraformRule {
  private static readonly SENSITIVE_NAME_PATTERNS: readonly RegExp[] = [
    /password/i, /passwd/i, /secret/i, /token/i, /cred/i,
    /private_key/i, /privatekey/i, /ssh_key/i,
    /api_key/i, /apikey/i, /conn_str/i, /connection_string/i,
    /oauth/i, /jwt/i
  ];

  constructor() {
    super(
      'ECS-002',
      'HIGH',
      'ECS task may not be using secure parameter storage for sensitive information',
      ['aws_ecs_task_definition']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_ecs_task_definition') return null;

    const containerDefinitions = resource.values?.container_definitions;
    if (!containerDefinitions || typeof containerDefinitions !== 'string') return null;

    try {
      const containers = JSON.parse(containerDefinitions);
      if (!Array.isArray(containers)) return null;

      for (const container of containers) {
        const envVars = container.environment;
        if (Array.isArray(envVars)) {
          const sensitiveVars = envVars.filter((env: any) =>
            this.isSensitiveName(env.name)
          );

          if (sensitiveVars.length > 0) {
            const names = sensitiveVars.map((env: any) => env.name).join(', ');
            return this.createScanResult(
              resource,
              projectName,
              `${this.description}. Potentially sensitive environment variables: ${names}`,
              'Store sensitive parameters in AWS Secrets Manager or SSM Parameter Store SecureString using the secrets block.'
            );
          }
        }
      }
    } catch {
      return null;
    }

    return null;
  }

  private isSensitiveName(name: unknown): boolean {
    if (typeof name !== 'string') return false;
    return TfEcs002Rule.SENSITIVE_NAME_PATTERNS.some(pattern => pattern.test(name));
  }
}

export default new TfEcs002Rule();
